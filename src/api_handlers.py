import json
from typing import Callable

from jinja2 import Environment, FileSystemLoader, select_autoescape
from urllib.parse import unquote
import os
import bcrypt
from datetime import datetime, timedelta
import io
import jwt

from src.db import UpdateData, FetchData, DeleteData, InsertData

current_dir = os.path.dirname(os.path.abspath(__file__))
templates_dir = os.path.join(current_dir, "templates")

SECRET = os.environ.get("SECRET")


current_dir = os.path.dirname(os.path.abspath(__file__))
templates_dir = os.path.join(current_dir, "templates")
env = Environment(
    loader=FileSystemLoader(templates_dir),
    autoescape=select_autoescape(["html", "xml"]),
)


def json_response(data: dict, status: int = 200) -> dict:
    status_map = {
        200: "200 OK",
        201: "201 Created",
        400: "400 Bad Request",
        401: "401 Unauthorized",
        403: "403 Forbidden",
        404: "404 Not Found",
        405: "405 Method Not Allowed",
    }

    body = json.dumps(data)
    headers = [("Content-Type", "application/json")]
    return {
        "status": status_map.get(status, "500 Internal Server Error"),
        "headers": headers,
        "body": body.encode("utf-8"),
    }


def read_request_body(environ: dict) -> dict:
    try:
        request_body_size = int(environ.get("CONTENT_LENGTH", 0))
    except (ValueError, TypeError):
        request_body_size = 0

    request_body = environ["wsgi.input"].read(request_body_size)
    environ["wsgi.input"] = io.BytesIO(request_body)
    if request_body_size == 0:
        return {}

    try:
        data = json.loads(request_body.decode("utf-8"))
        return data
    except json.JSONDecodeError:
        return {}


def generate_jwt(user_id: int) -> str:
    expiration = datetime.utcnow() + timedelta(hours=2)
    payload = {"user_id": user_id, "exp": expiration}
    return jwt.encode(payload, SECRET, algorithm="HS256")


def authenticate_request(environ: dict) -> int | None:
    auth_header = environ.get("HTTP_AUTHORIZATION")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        try:
            payload = jwt.decode(token, SECRET, algorithms=["HS256"])
            return payload["user_id"]
        except jwt.PyJWTError:
            return None
    return None


def require_auth(handler: Callable) -> Callable:
    def new_handler(environ: dict):
        user_id = authenticate_request(environ)
        if user_id is None:
            return json_response({"error": "Unauthorized"}, 401)

        return handler(environ, user_id)

    return new_handler


@require_auth
def handle_api_task_lists(environ, user_id: int) -> dict:
    user_role = FetchData().fetch_user_role(user_id)
    method = environ["REQUEST_METHOD"]
    if method == "GET":
        task_lists_data = []
        if user_role == "admin":
            task_lists = FetchData().fetch_all_task_lists()
        else:
            task_lists = FetchData().fetch_task_lists(user_id=user_id)
        for task_list in task_lists:
            task_lists_data.append({"id": task_list[0], "name": task_list[2]})

        return json_response({"task_lists": task_lists_data})

    if method == "POST" and user_role == "user":
        data = read_request_body(environ)
        list_name = data.get("list_name", "")
        if list_name:
            InsertData().insert_task_lists(name=list_name, user_id=user_id)
            return json_response({"message": "Task list created"}, 201)
        return json_response({"error": "Missing list name"}, 400)
    return json_response({"error": "Method Not Allowed"}, 405)


@require_auth
def handle_api_tasks(environ: dict, user_id: int) -> dict:
    path = environ["PATH_INFO"]
    list_id = unquote(path.strip("/").split("/")[-1])
    user_role = FetchData().fetch_user_role(user_id)

    if user_role != "admin":
        list_owner_id = FetchData().fetch_list_owner_id(list_id)
        if not list_owner_id or list_owner_id[0][0] != user_id:
            return json_response({"error": "Access denied"}, 403)

    method = environ["REQUEST_METHOD"]
    if method == "GET":
        tasks_data = []
        tasks = FetchData().fetch_tasks(list_id)
        for task in tasks:
            tasks_data.append({"id": task[1], "name": task[0]})
        return json_response({"tasks": tasks_data})

    if method == "POST" and user_role != "admin":
        data = read_request_body(environ)
        task_name = data.get("task_name", "")
        if task_name:
            InsertData().insert_tasks(task_name, list_id)
            return json_response({"message": "Task created successfully"}, 201)
        return json_response({"error": "Missing task name"}, 400)
    return json_response({"error": "Method Not Allowed"}, 405)


def handle_api_register(environ: dict) -> dict:
    if environ["REQUEST_METHOD"] != "POST":
        return json_response({"error": "Method Not Allowed"}, 405)
    data = read_request_body(environ)
    username = data.get("username", "")
    password = data.get("password", "")
    role = data.get("role", "user")

    existing_user = FetchData().fetch_user_by_username(username)
    if existing_user:
        return json_response({"error": "Username already exists"}, 400)
    if username and password:
        hashed_password = bcrypt.hashpw(
            password.encode(), bcrypt.gensalt()
        ).decode()
        InsertData().insert_user(username, hashed_password, role)
        return json_response({"message": "User registered successfully"}, 201)
    return json_response({"error": "Missing username or password"}, 400)


def handle_api_login(environ: dict) -> dict:
    if environ["REQUEST_METHOD"] != "POST":
        return json_response({"error": "Method Not Allowed"}, 405)
    data = read_request_body(environ)
    username = data.get("username", "")
    password = data.get("password", "")

    user = FetchData().fetch_user_by_username(username)
    if user and bcrypt.checkpw(password.encode(), user[0][2].encode()):
        jwt_token = generate_jwt(user[0][0])
        return json_response({"token": jwt_token})
    else:
        return json_response({"error": "Invalid username or password"}, 401)


@require_auth
def handle_api_delete_task_list(environ: dict, user_id: int) -> dict:
    path = environ["PATH_INFO"]
    list_id = path.split("/")[-2]
    DeleteData().delete_task_list(list_id, user_id)
    return json_response({"message": "Task list deleted successfully"})


@require_auth
def handle_api_delete_task(environ: dict, user_id: int) -> dict:
    path = environ["PATH_INFO"]
    parts = path.split("/")
    task_id = parts[5]
    DeleteData().delete_task(task_id, user_id)
    return json_response({"message": "Task deleted successfully"})


@require_auth
def handle_api_edit_task_list(environ: dict, user_id: int) -> dict:
    if environ["REQUEST_METHOD"] != "POST":
        return json_response({"error": "Method Not Allowed"}, 405)
    path = environ["PATH_INFO"]
    list_id = path.split("/")[-2]
    list_owner_id = FetchData().fetch_list_owner_id(list_id)
    if not list_owner_id or list_owner_id[0][0] != user_id:
        return json_response({"error": "Access denied"}, 403)

    data = read_request_body(environ)
    new_name = data.get("list_name", "")
    if new_name:
        UpdateData().update_task_list(list_id, user_id, new_name)
        return json_response({"message": "Task list updated successfully"})
    return json_response({"error": "Missing new name for the task list"}, 400)


@require_auth
def handle_api_edit_task(environ: dict, user_id: int) -> dict:
    if environ["REQUEST_METHOD"] != "POST":
        return json_response({"error": "Method Not Allowed"}, 405)
    path = environ["PATH_INFO"]
    parts = path.split("/")
    list_id, task_id = parts[3], parts[5]

    list_owner_id = FetchData().fetch_list_owner_id(list_id)
    if not list_owner_id or list_owner_id[0][0] != user_id:
        return json_response({"error": "Access denied"}, 403)

    data = read_request_body(environ)
    new_name = data.get("task_name", "")
    if new_name:
        UpdateData().update_task(task_id, list_id, user_id, new_name)
        return json_response({"message": "Task updated successfully"})
    return json_response({"error": "Missing new name for the task"}, 400)


def api_not_found() -> dict:
    return json_response({"error": "Not found"}, 404)
