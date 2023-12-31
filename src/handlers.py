from http.cookies import SimpleCookie
from typing import Callable
from jinja2 import Environment, FileSystemLoader, select_autoescape
from urllib.parse import unquote
import urllib
import os
import bcrypt
from datetime import datetime, timedelta
import secrets
import io

from src.db import UpdateData, FetchData, DeleteData, InsertData


current_dir = os.path.dirname(os.path.abspath(__file__))
templates_dir = os.path.join(current_dir, "templates")
env = Environment(
    loader=FileSystemLoader(templates_dir),
    autoescape=select_autoescape(["html", "xml"]),
)


def read_request_body(environ: dict) -> dict:
    try:
        request_body_size = int(environ.get("CONTENT_LENGTH", 0))
    except (ValueError, TypeError):
        request_body_size = 0

    request_body = environ["wsgi.input"].read(request_body_size)
    environ["wsgi.input"] = io.BytesIO(request_body)
    try:
        data = urllib.parse.parse_qs(request_body.decode("utf-8"))
        return data
    except UnicodeDecodeError:
        return {}


def get_csrf_token(environ: dict) -> str | None:
    cookies = SimpleCookie(environ.get("HTTP_COOKIE", ""))
    session_id = (
        cookies.get("session_id").value if cookies.get("session_id") else None
    )
    csrf_token = None
    if session_id:
        session_info = FetchData().fetch_session(session_id)
        if session_info:
            csrf_token = session_info[0][1]
    return csrf_token


def authenticate_request(environ: dict) -> str:
    cookies = SimpleCookie(environ.get("HTTP_COOKIE", ""))
    session_cookie = cookies.get("session_id")
    if session_cookie:
        session_id = session_cookie.value
        session = FetchData().fetch_session(session_id)
        if not session or not session[0]:
            return
        user_id, _, created_at = session[0]
        if datetime.utcnow() - created_at < timedelta(hours=2):
            return user_id


def require_auth(handler: Callable) -> Callable:
    def new_handler(environ: dict) -> dict:
        user_id = authenticate_request(environ)
        if user_id is None:
            return {
                "status": "303 See Other",
                "headers": [("Location", "/login")],
                "body": b"Please login to access this page",
            }
        return handler(environ, user_id)

    return new_handler


def validate_csrf_token(environ: dict, csrf_token_submitted: str) -> bool:
    session_cookie = SimpleCookie(environ.get("HTTP_COOKIE", ""))
    session_id = (
        session_cookie.get("session_id").value
        if session_cookie.get("session_id")
        else None
    )
    if not session_id or not csrf_token_submitted:
        return False

    session_info = FetchData().fetch_session(session_id)
    csrf_token_session = session_info[0][1] if session_info else None
    return csrf_token_submitted == csrf_token_session


def require_csrf_token(handler: Callable) -> Callable:
    def new_handler(environ: dict, user_id: int) -> dict:
        if environ["REQUEST_METHOD"] == "POST":
            data = read_request_body(environ)
            csrf_token_submitted = data.get("csrf_token", [""])[0]
            if not validate_csrf_token(environ, csrf_token_submitted):
                return {
                    "status": "403 Forbidden",
                    "headers": [("Content-type", "text/html")],
                    "body": b"Invalid CSRF token",
                }

        return handler(environ, user_id)

    return new_handler


@require_auth
@require_csrf_token
def handle_task_lists(environ: dict, user_id: int) -> dict:
    user_role = FetchData().fetch_user_role(user_id)
    method = environ["REQUEST_METHOD"]
    if method == "GET":
        if user_role == "admin":
            task_lists = FetchData().fetch_all_task_lists()
        else:
            task_lists = FetchData().fetch_task_lists(user_id=user_id)

        csrf_token = get_csrf_token(environ)
        template = env.get_template("task_lists.html")
        response_body = template.render(
            {
                "task_lists": task_lists,
                "is_admin": user_role == "admin",
                "csrf_token": csrf_token,
            }
        )
        return {
            "status": "200 OK",
            "headers": [("Content-type", "text/html")],
            "body": response_body.encode(),
        }

    if method == "POST":
        data = read_request_body(environ)

        list_name = data.get("list_name", [""])[0]
        if list_name:
            InsertData().insert_task_lists(name=list_name, user_id=user_id)
        return {
            "status": "303 See Other",
            "headers": [("Location", "/task_lists")],
            "body": b"",
        }


@require_auth
@require_csrf_token
def handle_tasks(environ: dict, user_id: int) -> dict:
    path = environ["PATH_INFO"]
    list_id = unquote(path.strip("/").split("/")[-1])
    user_role = FetchData().fetch_user_role(user_id)

    if user_role != "admin":
        list_owner_id = FetchData().fetch_list_owner_id(list_id)
        if not list_owner_id or list_owner_id[0][0] != user_id:
            return {
                "status": "403 Forbidden",
                "headers": [("Content-type", "text/html")],
                "body": b"Access denied",
            }

    method = environ["REQUEST_METHOD"]
    if method == "GET":
        list_name = FetchData().fetch_task_lists(
            user_id=user_id, get_name=True, list_id=list_id
        )
        list_name = list_name[0][0] if list_name else "List"
        tasks = FetchData().fetch_tasks(list_id)

        csrf_token = get_csrf_token(environ)
        template = env.get_template("tasks.html")
        response_body = template.render(
            {
                "csrf_token": csrf_token,
                "tasks": tasks,
                "list_id": list_id,
                "list_name": list_name,
                "is_admin": user_role == "admin",
            }
        )
        return {
            "status": "200 OK",
            "headers": [("Content-type", "text/html")],
            "body": response_body.encode(),
        }

    if method == "POST" and user_role != "admin":
        data = read_request_body(environ)
        task_name = data.get("task_name", [""])[0]
        if task_name:
            InsertData().insert_tasks(task_name, list_id)
        return {
            "status": "303 See Other",
            "headers": [("Location", f"/task_lists/{list_id}")],
            "body": b"",
        }


def handle_register(environ: dict) -> dict:
    method = environ["REQUEST_METHOD"]
    if method == "GET":
        path_to_register = os.path.join(templates_dir, "register.html")
        with open(path_to_register, "r", encoding="utf-8") as file:
            response = file.read()
        return {
            "status": "200 OK",
            "headers": [("Content-type", "text/html")],
            "body": response.encode("utf-8"),
        }

    if method == "POST":
        data = read_request_body(environ)
        username = data.get("username", [""])[0]
        existing_user = FetchData().fetch_user_by_username(username)
        if existing_user:
            return {
                "status": "200 OK",
                "headers": [("Content-type", "text/html")],
                "body": b"Username already exists, please choose another one.",
            }

        password = data.get("password", [""])[0]
        role = data.get("role", ["user"])[0]

        if username and password:
            hashed_password = bcrypt.hashpw(
                password.encode(), bcrypt.gensalt()
            ).decode()

            InsertData().insert_user(username, hashed_password, role)

        return {
            "status": "303 See Other",
            "headers": [("Location", "/login")],
            "body": b"",
        }


def handle_login(environ: dict) -> dict:
    method = environ["REQUEST_METHOD"]
    if method == "GET":
        path_to_login = os.path.join(templates_dir, "login.html")
        with open(path_to_login, "r", encoding="utf-8") as file:
            response = file.read()
        return {
            "status": "200 OK",
            "headers": [("Content-type", "text/html")],
            "body": response.encode("utf-8"),
        }

    if method == "POST":
        data = read_request_body(environ)
        username = data.get("username", [""])[0]
        password = data.get("password", [""])[0]

        user = FetchData().fetch_user_by_username(username)
        if user and bcrypt.checkpw(password.encode(), user[0][2].encode()):
            csrf_token = secrets.token_hex(16)
            session_id = InsertData().insert_session(user[0][0], csrf_token)

            response_headers = [
                ("Content-type", "text/html"),
                ("Set-Cookie", f"session_id={session_id}; HttpOnly; Path=/"),
                ("Location", "/task_lists"),
            ]
            return {
                "status": "303 See Other",
                "headers": response_headers,
                "body": b"Login successful, redirecting...",
            }
        else:
            return {
                "status": "401 Unauthorized",
                "headers": [("Content-type", "text/html")],
                "body": b"Invalid username or password",
            }


@require_auth
def handle_delete_task_list(environ: dict, user_id: int) -> dict:
    path = environ["PATH_INFO"]
    list_id = path.split("/")[-2]
    DeleteData().delete_task_list(list_id, user_id)
    return {
        "status": "303 See Other",
        "headers": [("Location", "/task_lists")],
        "body": b"",
    }


@require_auth
def handle_delete_task(environ: dict, user_id: int) -> dict:
    path = environ["PATH_INFO"]
    parts = path.split("/")
    list_id = parts[2]
    task_id = parts[4]
    DeleteData().delete_task(task_id, user_id)
    return {
        "status": "303 See Other",
        "headers": [("Location", f"/task_lists/{list_id}")],
        "body": b"",
    }


@require_auth
def handle_edit_task_list(environ: dict, user_id: int) -> dict:
    method = environ["REQUEST_METHOD"]
    path = environ["PATH_INFO"]
    list_id = path.split("/")[-2]

    list_owner_id = FetchData().fetch_list_owner_id(list_id)
    if not list_owner_id or list_owner_id[0][0] != user_id:
        return {
            "status": "403 Forbidden",
            "headers": [("Content-type", "text/html")],
            "body": b"Access denied",
        }

    if method == "GET":
        template = env.get_template("edit_task_list.html")
        response_body = template.render({"list_id": list_id})
        return {
            "status": "200 OK",
            "headers": [("Content-type", "text/html")],
            "body": response_body.encode(),
        }
    elif method == "POST":
        data = read_request_body(environ)
        new_name = data.get("list_name", [""])[0]
        if new_name:
            UpdateData().update_task_list(list_id, user_id, new_name)
        return {
            "status": "303 See Other",
            "headers": [("Location", "/task_lists")],
            "body": b"",
        }


@require_auth
def handle_edit_task(environ: dict, user_id: int) -> dict:
    method = environ["REQUEST_METHOD"]
    path = environ["PATH_INFO"]
    parts = path.split("/")
    list_id, task_id = parts[2], parts[4]

    list_owner_id = FetchData().fetch_list_owner_id(list_id)
    if not list_owner_id or list_owner_id[0][0] != user_id:
        return {
            "status": "403 Forbidden",
            "headers": [("Content-type", "text/html")],
            "body": b"Access denied",
        }

    if method == "GET":
        template = env.get_template("edit_task.html")
        response_body = template.render(
            {"list_id": list_id, "task_id": task_id}
        )
        return {
            "status": "200 OK",
            "headers": [("Content-type", "text/html")],
            "body": response_body.encode(),
        }
    elif method == "POST":
        data = read_request_body(environ)
        new_name = data.get("task_name", [""])[0]
        if new_name:
            UpdateData().update_task(task_id, list_id, user_id, new_name)
        return {
            "status": "303 See Other",
            "headers": [("Location", f"/task_lists/{list_id}")],
            "body": b"",
        }


def not_found() -> dict:
    return {
        "status": "404 Not Found",
        "headers": [("Content-type", "text/html")],
        "body": b"Not found",
    }
