import io
from unittest.mock import patch

import bcrypt
import jwt
import pytest

from src.app import app

from webtest import TestApp
from src.api_handlers import (
    json_response,
    read_request_body,
    generate_jwt,
    authenticate_request,
    SECRET,
    require_auth,
)


@pytest.fixture
def testapp():
    return TestApp(app)


def test_json_response():
    data = {"message": "Test"}
    response = json_response(data, status=200)
    assert response["status"] == "200 OK"
    assert response["headers"] == [("Content-Type", "application/json")]
    assert response["body"] == b'{"message": "Test"}'


def test_read_request_body():
    environ = {
        "wsgi.input": io.BytesIO(b'{"key": "value"}'),
        "CONTENT_LENGTH": "16",
    }
    result = read_request_body(environ)
    assert result == {"key": "value"}

    environ = {"wsgi.input": io.BytesIO(b""), "CONTENT_LENGTH": "0"}
    result = read_request_body(environ)
    assert result == {}

    environ = {"wsgi.input": io.BytesIO(b"not a json"), "CONTENT_LENGTH": "10"}
    result = read_request_body(environ)
    assert result == {}


def test_generate_jwt():
    user_id = 1
    token = generate_jwt(user_id)
    decoded = jwt.decode(token, SECRET, algorithms=["HS256"])
    assert decoded["user_id"] == user_id


def test_authenticate_request_success():
    user_id = 1
    token = generate_jwt(user_id)
    environ = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
    assert authenticate_request(environ) == user_id


def test_require_auth_success():
    def mock_handler(environ, user_id):
        return json_response({"message": "Success"}, 200)

    decorated_handler = require_auth(mock_handler)
    user_id = 1
    token = generate_jwt(user_id)
    environ = {"HTTP_AUTHORIZATION": f"Bearer {token}"}
    response = decorated_handler(environ)
    assert response == json_response({"message": "Success"}, 200)


def test_authenticate_request_fail():
    environ = {"HTTP_AUTHORIZATION": "Bearer invalid_token"}
    assert authenticate_request(environ) is None

    environ = {}
    assert authenticate_request(environ) is None


def test_require_auth_fail():
    def mock_handler(environ, user_id):
        return json_response({"message": "Success"}, 200)

    decorated_handler = require_auth(mock_handler)
    environ = {"HTTP_AUTHORIZATION": "Bearer invalid_token"}
    response = decorated_handler(environ)
    assert response == json_response({"error": "Unauthorized"}, 401)

    environ = {}
    response = decorated_handler(environ)
    assert response == json_response({"error": "Unauthorized"}, 401)


def test_api_task_lists_get_admin(testapp):
    with patch("src.api_handlers.authenticate_request", return_value=1):
        with patch(
            "src.api_handlers.FetchData.fetch_user_role", return_value="admin"
        ):
            with patch(
                "src.api_handlers.FetchData.fetch_all_task_lists",
                return_value=[(1, 1, "Task List 1"), (2, 2, "Task List 2")],
            ):
                response = testapp.get(
                    "/api/task_lists",
                    headers={"Authorization": "Bearer correct_token"},
                )
                assert response.status_code == 200
                assert response.json == {
                    "task_lists": [
                        {"id": 1, "name": "Task List 1"},
                        {"id": 2, "name": "Task List 2"},
                    ]
                }


def test_api_task_lists_post_user(testapp):
    with patch("src.api_handlers.authenticate_request", return_value=1):
        with patch(
            "src.api_handlers.FetchData.fetch_user_role", return_value="user"
        ):
            with patch("src.api_handlers.InsertData.insert_task_lists"):
                response = testapp.post_json(
                    "/api/task_lists",
                    {"list_name": "New List"},
                    headers={
                        "Authorization": "Bearer correct_token",
                        "Content-Type": "application/json",
                    },
                )
                assert response.status_code == 201
                assert response.json == {"message": "Task list created"}


def test_handle_api_tasks_get_user(testapp):
    list_id = 1
    with patch("src.api_handlers.authenticate_request", return_value=1):
        with patch(
            "src.api_handlers.FetchData.fetch_user_role", return_value="user"
        ):
            with patch(
                "src.api_handlers.FetchData.fetch_tasks",
                return_value=[("Task 1", 1)],
            ):
                with patch(
                    "src.api_handlers.FetchData.fetch_list_owner_id",
                    return_value=[(1,)],
                ):
                    response = testapp.get(
                        f"/api/task_lists/{list_id}",
                        headers={"Authorization": "Bearer user_token"},
                    )
                    assert response.status_code == 200
                    assert {
                        "tasks": [{"id": 1, "name": "Task 1"}]
                    } == response.json


def test_handle_api_tasks_post_user(testapp):
    list_id = 1
    task_name = "New Task"
    with patch("src.api_handlers.authenticate_request", return_value=1):
        with patch(
            "src.api_handlers.FetchData.fetch_user_role", return_value="user"
        ):
            with patch(
                "src.api_handlers.InsertData.insert_tasks"
            ):
                with patch(
                    "src.api_handlers.FetchData.fetch_list_owner_id",
                    return_value=[(1,)],
                ):
                    response = testapp.post_json(
                        f"/api/task_lists/{list_id}",
                        {"task_name": task_name},
                        headers={"Authorization": "Bearer user_token"},
                    )
                    assert response.status_code == 201
                    assert response.json == {
                        "message": "Task created successfully"
                    }


def test_handle_api_register_success(testapp):
    with patch(
        "src.api_handlers.FetchData.fetch_user_by_username", return_value=None
    ):
        with patch("src.api_handlers.InsertData.insert_user"):
            user_data = {
                "username": "newuser",
                "password": "password123",
                "role": "user",
            }
            response = testapp.post_json("/api/register", user_data)
            assert response.status_code == 201
            assert response.json == {"message": "User registered successfully"}


def test_handle_api_register_existing_user(testapp):
    with patch(
        "src.api_handlers.FetchData.fetch_user_by_username",
        return_value=[(1, "existinguser", "hashed_password", "user")],
    ):
        user_data = {
            "username": "existinguser",
            "password": "password123",
            "role": "user",
        }
        response = testapp.get("/api/login", status=405)
        assert response.status_code == 405
        response = testapp.post_json("/api/register", user_data, status=400)
        assert response.status_code == 400
        assert response.json == {"error": "Username already exists"}


def test_handle_api_login_success(testapp):
    username = "testuser"
    password = "password"
    hashed_password = bcrypt.hashpw(
        password.encode(), bcrypt.gensalt()
    ).decode()
    with patch(
        "src.api_handlers.FetchData.fetch_user_by_username",
        return_value=[(1, username, hashed_password, "user")],
    ):
        with patch("src.api_handlers.generate_jwt", return_value="jwt_token"):
            response = testapp.post_json(
                "/api/login", {"username": username, "password": password}
            )
            assert response.status_code == 200
            assert "token" in response.json


def test_handle_api_login_fail(testapp):
    username = "testuser"
    password = "wrong_password"
    hashed_correct_password = bcrypt.hashpw(
        "correct_password".encode(), bcrypt.gensalt()
    ).decode()
    with patch(
        "src.api_handlers.FetchData.fetch_user_by_username",
        return_value=[(1, username, hashed_correct_password, "user")],
    ):
        response = testapp.get("/api/login", status=405)
        assert response.status_code == 405
        response = testapp.post_json(
            "/api/login",
            {"username": username, "password": password},
            status=401,
        )
        assert response.status_code == 401
        assert response.json == {"error": "Invalid username or password"}


def test_handle_api_delete_task_list_success(testapp):
    list_id = 1
    with patch("src.api_handlers.authenticate_request", return_value=1):
        with patch("src.api_handlers.DeleteData.delete_task_list"):
            response = testapp.get(
                f"/api/task_lists/{list_id}/delete",
                headers={"Authorization": "Bearer valid_token"},
            )
            assert response.status_code == 200
            assert response.json == {
                "message": "Task list deleted successfully"
            }


def test_handle_api_delete_task_success(testapp):
    list_id = 1
    task_id = 1
    with patch(
        "src.api_handlers.authenticate_request", return_value="user_id"
    ):
        with patch("src.api_handlers.DeleteData.delete_task"):
            response = testapp.get(
                f"/api/task_lists/{list_id}/tasks/{task_id}/delete",
                headers={"Authorization": "Bearer valid_token"},
            )
            assert response.status_code == 200
            assert response.json == {"message": "Task deleted successfully"}


def test_handle_api_edit_task_list(testapp):
    list_id = 1
    new_name = "Updated List Name"
    with patch("src.api_handlers.authenticate_request", return_value=1):
        with patch(
            "src.api_handlers.FetchData.fetch_list_owner_id",
            return_value=[(1,)],
        ):
            with patch(
                "src.api_handlers.UpdateData.update_task_list"
            ):
                response = testapp.get(
                    f"/api/task_lists/{list_id}/edit", status=405
                )
                assert response.status_code == 405
                response = testapp.post_json(
                    f"/api/task_lists/{list_id}/edit",
                    {"list_name": new_name},
                    headers={"Authorization": "Bearer valid_token"},
                )
                assert response.status_code == 200
                assert response.json == {
                    "message": "Task list updated successfully"
                }


def test_handle_api_edit_task(testapp):
    list_id = 1
    task_id = 1
    new_name = "Updated Task Name"
    with patch("src.api_handlers.authenticate_request", return_value=1):
        with patch(
            "src.api_handlers.FetchData.fetch_list_owner_id",
            return_value=[(1,)],
        ):
            with patch("src.api_handlers.UpdateData.update_task"):
                response = testapp.get(
                    f"/api/task_lists/{list_id}/tasks/{task_id}/edit",
                    status=405,
                )
                assert response.status_code == 405
                response = testapp.post_json(
                    f"/api/task_lists/{list_id}/tasks/{task_id}/edit",
                    {"task_name": new_name},
                    headers={"Authorization": "Bearer valid_token"},
                )
                assert response.status_code == 200
                assert response.json == {
                    "message": "Task updated successfully"
                }


def test_api_not_found(testapp):
    response = testapp.get("/api/wrong!", expect_errors=True, status=404)
    assert response.status_code == 404
    assert response.json == {"error": "Not found"}
