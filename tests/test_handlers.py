import io
from datetime import datetime, timedelta
from unittest.mock import patch

import bcrypt
import pytest
from webtest import TestApp
from src.app import app
from src.handlers import (
    read_request_body,
    get_csrf_token,
    authenticate_request,
    require_auth,
    validate_csrf_token,
    require_csrf_token,
)


@pytest.fixture
def testapp():
    return TestApp(app)


def test_read_request_body_with_data():
    data = "key1=value1&key2=value2"
    environ = {
        "wsgi.input": io.BytesIO(data.encode()),
        "CONTENT_LENGTH": len(data),
    }
    result = read_request_body(environ)
    assert result == {"key1": ["value1"], "key2": ["value2"]}


def test_read_request_body_decode_error():
    environ = {"wsgi.input": io.BytesIO(b"\x80\x81\x82"), "CONTENT_LENGTH": 3}
    assert read_request_body(environ) == {}


def test_read_request_body_empty():
    environ = {"wsgi.input": io.BytesIO(b""), "CONTENT_LENGTH": 0}
    assert read_request_body(environ) == {}


def test_get_csrf_token_no_cookies():
    environ = {}
    assert get_csrf_token(environ) is None


def test_get_csrf_token_with_cookies_no_session():
    environ = {"HTTP_COOKIE": "session_id=test_session"}
    with patch("src.handlers.FetchData.fetch_session", return_value=None):
        assert get_csrf_token(environ) is None


def test_get_csrf_token_with_valid_session():
    environ = {"HTTP_COOKIE": "session_id=test_session"}
    session_info = [("test_session", "test_csrf_token")]
    with patch(
        "src.handlers.FetchData.fetch_session", return_value=session_info
    ):
        assert get_csrf_token(environ) == "test_csrf_token"


def test_authenticate_request_no_cookies():
    environ = {}
    assert authenticate_request(environ) is None


def test_authenticate_request_session_not_found():
    environ = {"HTTP_COOKIE": "session_id=test_session"}
    with patch("src.handlers.FetchData.fetch_session", return_value=None):
        assert authenticate_request(environ) is None


def test_authenticate_request_session_expired():
    environ = {"HTTP_COOKIE": "session_id=test_session"}
    expired_time = datetime.utcnow() - timedelta(hours=3)
    session_info = [(1, "csrf_token", expired_time)]
    with patch(
        "src.handlers.FetchData.fetch_session", return_value=session_info
    ):
        assert authenticate_request(environ) is None


def test_authenticate_request_valid_session():
    environ = {"HTTP_COOKIE": "session_id=test_session"}
    valid_time = datetime.utcnow() - timedelta(minutes=30)
    session_info = [(1, "csrf_token", valid_time)]
    with patch(
        "src.handlers.FetchData.fetch_session", return_value=session_info
    ):
        assert authenticate_request(environ) == 1


def test_require_auth_unauthenticated():
    def mock_handler(environ, user_id):
        return "handler_called"

    environ = {}
    new_handler = require_auth(mock_handler)
    response = new_handler(environ)
    assert response["status"] == "303 See Other"
    assert response["headers"] == [("Location", "/login")]


def test_require_auth_authenticated():
    def mock_handler(environ, user_id):
        return "handler_called"

    environ = {"HTTP_COOKIE": "session_id=test_session"}
    valid_time = datetime.utcnow() - timedelta(minutes=30)
    session_info = [(1, "csrf_token", valid_time)]

    with patch(
        "src.handlers.FetchData.fetch_session", return_value=session_info
    ):
        new_handler = require_auth(mock_handler)
        assert new_handler(environ) == "handler_called"


def test_validate_csrf_token_no_token():
    environ = {}
    assert not validate_csrf_token(environ, None)


def test_validate_csrf_token_mismatch_token():
    environ = {"HTTP_COOKIE": "session_id=test_session"}
    session_info = [(1, "csrf_token")]
    with patch(
        "src.handlers.FetchData.fetch_session", return_value=session_info
    ):
        assert not validate_csrf_token(environ, "wrong_token")


def test_validate_csrf_token_valid_token():
    environ = {"HTTP_COOKIE": "session_id=test_session"}
    session_info = [(1, "correct_token")]
    with patch(
        "src.handlers.FetchData.fetch_session", return_value=session_info
    ):
        assert validate_csrf_token(environ, "correct_token")


def test_require_csrf_token_invalid():
    def mock_handler(environ, user_id):
        return "handler_called"

    environ = {
        "REQUEST_METHOD": "POST",
        "HTTP_COOKIE": "session_id=test_session",
        "wsgi.input": io.BytesIO(b"csrf_token=wrong_token"),
    }
    with patch(
        "src.handlers.FetchData.fetch_session",
        return_value=[(1, "correct_token")],
    ):
        new_handler = require_csrf_token(mock_handler)
        response = new_handler(environ, 1)
        assert response["status"] == "403 Forbidden"


def test_handle_task_lists_get_admin(testapp):
    with patch("src.handlers.FetchData.fetch_user_role", return_value="admin"):
        with patch(
            "src.handlers.FetchData.fetch_all_task_lists",
            return_value=[(1, 1, "Test List")],
        ):
            with patch("src.handlers.get_csrf_token", return_value="token"):
                with patch(
                    "src.handlers.authenticate_request",
                    return_value=1,
                ):
                    response = testapp.get(
                        "/task_lists",
                        headers={"Cookie": "session_id=test_session"},
                    )
                    assert response.status_code == 200
                    assert "All Task Lists" in response.text
                    assert "Test List" in response.text


def test_handle_task_lists_get_user(testapp):
    with patch("src.handlers.FetchData.fetch_user_role", return_value="user"):
        with patch(
            "src.handlers.FetchData.fetch_task_lists",
            return_value=[(2, 2, "User Task List")],
        ):
            with patch("src.handlers.get_csrf_token", return_value="token"):
                with patch(
                    "src.handlers.authenticate_request", return_value=1
                ):
                    response = testapp.get(
                        "/task_lists",
                        headers={"Cookie": "session_id=test_session"},
                    )
                    assert response.status_code == 200
                    assert "Your Task Lists" in response.text
                    assert "User Task List" in response.text


def test_handle_task_lists_post(testapp):
    with patch("src.handlers.FetchData.fetch_user_role", return_value="user"):
        with patch("src.handlers.InsertData.insert_task_lists"):
            with patch("src.handlers.validate_csrf_token", return_value=True):
                with patch(
                    "src.handlers.authenticate_request", return_value=1
                ):
                    form_data = {
                        "list_name": "New Task List",
                        "csrf_token": "token",
                    }
                    response = testapp.post(
                        "/task_lists",
                        params=form_data,
                        headers={"Cookie": "session_id=test_session"},
                    )
                    assert response.status_code == 303
                    assert response.headers["Location"] == "/task_lists"


def test_handle_tasks_get_user(testapp):
    list_id = 1
    with patch("src.handlers.FetchData.fetch_user_role", return_value="user"):
        with patch(
            "src.handlers.FetchData.fetch_task_lists",
            return_value=[
                (
                    1,
                    1,
                    "List Name",
                )
            ],
        ):
            with patch(
                "src.handlers.FetchData.fetch_tasks",
                return_value=[("Task 1", 1)],
            ):
                with patch(
                    "src.handlers.FetchData.fetch_list_owner_id",
                    return_value=[(1,)],
                ):
                    with patch(
                        "src.handlers.get_csrf_token", return_value="token"
                    ):
                        with patch(
                            "src.handlers.authenticate_request",
                            return_value=1,
                        ):
                            response = testapp.get(
                                f"/task_lists/{list_id}",
                                headers={"Cookie": "session_id=test_session"},
                            )
                            assert response.status_code == 200
                            assert "Task 1" in response.text
                            assert (
                                f"/task_lists/{list_id}/tasks/1/edit"
                                in response.text
                            )
                            assert (
                                'name="csrf_token" value="token"'
                                in response.text
                            )


def test_handle_tasks_post(testapp):
    list_id = 1
    with patch("src.handlers.FetchData.fetch_user_role", return_value="user"):
        with patch("src.handlers.InsertData.insert_tasks"):
            with patch("src.handlers.validate_csrf_token", return_value=True):
                with patch(
                    "src.handlers.FetchData.fetch_list_owner_id",
                    return_value=[(1,)],
                ):
                    with patch(
                        "src.handlers.authenticate_request", return_value=1
                    ):
                        form_data = {
                            "task_name": "New Task",
                            "csrf_token": "token",
                        }
                        response = testapp.post(
                            f"/task_lists/{list_id}",
                            params=form_data,
                            headers={"Cookie": "session_id=test_session"},
                        )
                        assert response.status_code == 303
                        assert (
                            response.headers["Location"]
                            == f"/task_lists/{list_id}"
                        )


def test_register_page(testapp):
    response = testapp.get("/register")
    assert response.status_code == 200
    assert '<form action="/register" method="post">' in response.text


def test_register_post_existing_user(testapp):
    with patch(
        "src.handlers.FetchData.fetch_user_by_username", return_value=True
    ):
        form = {
            "username": "existing_user",
            "password": "password",
            "role": "user",
        }
        response = testapp.post("/register", form)
        assert response.status_code == 200
        assert "Username already exists" in response.text


def test_register_post_new_user(testapp):
    with patch(
        "src.handlers.FetchData.fetch_user_by_username", return_value=False
    ):
        with patch("src.handlers.InsertData.insert_user"):
            form = {
                "username": "new_user",
                "password": "password",
                "role": "user",
            }
            response = testapp.post("/register", form)
            assert response.status_code == 303
            assert response.headers["Location"] == "/login"


def test_handle_login_get(testapp):
    response = testapp.get("/login")
    assert response.status_code == 200
    assert "Username:" in response.text
    assert "Password:" in response.text
    assert "Login" in response.text
    assert "Register here" in response.text


def test_handle_login_post_success(testapp):
    username = "test_user"
    password = "test_password"
    hashed_password = bcrypt.hashpw(
        password.encode(), bcrypt.gensalt()
    ).decode()
    with patch(
        "src.handlers.FetchData.fetch_user_by_username",
        return_value=[(1, username, hashed_password, "user")],
    ):
        with patch(
            "src.handlers.InsertData.insert_session",
            return_value="test_session_id",
        ):
            form_data = {"username": username, "password": password}
            response = testapp.post("/login", params=form_data)
            assert response.status_code == 303
            assert response.headers["Location"] == "/task_lists"
            assert (
                "session_id=test_session_id" in response.headers["Set-Cookie"]
            )


def test_handle_login_post_fail(testapp):
    username = "test_user"
    password = "wrong_password"
    hashed_correct_password = bcrypt.hashpw(
        "test_password".encode(), bcrypt.gensalt()
    ).decode()
    with patch(
        "src.handlers.FetchData.fetch_user_by_username",
        return_value=[(1, username, hashed_correct_password, "user")],
    ):
        form_data = {"username": username, "password": password}
        response = testapp.post("/login", params=form_data, status=401)
        assert response.status_code == 401
        assert "Invalid username or password" in response.text


def test_handle_delete_task_list(testapp):
    list_id = 1
    user_id = 1
    with patch(
        "src.handlers.FetchData.fetch_user_by_username",
        return_value=[(user_id, "username", "password_hash", "user")],
    ):
        with patch("src.handlers.authenticate_request", return_value=user_id):
            with patch("src.handlers.DeleteData.delete_task_list"):
                response = testapp.post(f"/task_lists/{list_id}/delete")
                assert response.status_code == 303
                assert response.headers["Location"] == "/task_lists"


def test_handle_delete_task(testapp):
    list_id = 1
    task_id = 2
    user_id = 1
    with patch(
        "src.handlers.FetchData.fetch_user_by_username",
        return_value=[(user_id, "username", "password_hash", "user")],
    ):
        with patch("src.handlers.authenticate_request", return_value=user_id):
            with patch("src.handlers.DeleteData.delete_task"):
                response = testapp.post(
                    f"/task_lists/{list_id}/tasks/{task_id}/delete"
                )
                assert response.status_code == 303
                assert response.headers["Location"] == f"/task_lists/{list_id}"


def test_handle_edit_task_list_get(testapp):
    list_id = 1
    user_id = 1
    with patch(
        "src.handlers.FetchData.fetch_list_owner_id", return_value=[(user_id,)]
    ):
        with patch("src.handlers.authenticate_request", return_value=user_id):
            response = testapp.get(f"/task_lists/{list_id}/edit")
            assert response.status_code == 200
            assert (
                '<form action="/task_lists/1/edit" method="post">'
                in response.text
            )


def test_handle_edit_task_list_post(testapp):
    list_id = 1
    new_list_name = "Updated List Name"
    user_id = 1
    with patch(
        "src.handlers.FetchData.fetch_list_owner_id", return_value=[(user_id,)]
    ):
        with patch("src.handlers.authenticate_request", return_value=user_id):
            with patch(
                "src.handlers.UpdateData.update_task_list"
            ):
                form_data = {"list_name": new_list_name}
                response = testapp.post(
                    f"/task_lists/{list_id}/edit", params=form_data
                )

                assert response.status_code == 303
                assert response.headers["Location"] == "/task_lists"


def test_handle_edit_task_get(testapp):
    list_id = 1
    task_id = 2
    user_id = 1
    with patch(
        "src.handlers.FetchData.fetch_list_owner_id", return_value=[(user_id,)]
    ):
        with patch("src.handlers.authenticate_request", return_value=user_id):
            response = testapp.get(
                f"/task_lists/{list_id}/tasks/{task_id}/edit"
            )
            assert response.status_code == 200
            assert (
                '<form action="/task_lists/1/tasks/2/edit" method="post">'
                in response.text
            )


def test_handle_edit_task_post(testapp):
    list_id = 1
    task_id = 2
    new_task_name = "Updated Task Name"
    user_id = 1
    with patch(
        "src.handlers.FetchData.fetch_list_owner_id", return_value=[(user_id,)]
    ):
        with patch("src.handlers.authenticate_request", return_value=user_id):
            with patch("src.handlers.UpdateData.update_task"):
                form_data = {"task_name": new_task_name}
                response = testapp.post(
                    f"/task_lists/{list_id}/tasks/{task_id}/edit",
                    params=form_data,
                )
                assert response.status_code == 303
                assert response.headers["Location"] == f"/task_lists/{list_id}"


def test_not_found(testapp):
    response = testapp.get("/wrong!", status=404)
    assert response.status_code == 404
    assert response.headers["Content-type"] == "text/html"
    assert response.text == "Not found"
