import os
import re
from typing import Callable


from src.api_handlers import (
    handle_api_task_lists,
    handle_api_tasks,
    api_not_found,
    handle_api_edit_task,
    handle_api_edit_task_list,
    handle_api_delete_task,
    handle_api_delete_task_list,
    handle_api_login,
    handle_api_register,
)
from src.handlers import (
    not_found,
    handle_edit_task,
    handle_edit_task_list,
    handle_delete_task,
    handle_delete_task_list,
    handle_login,
    handle_register,
    handle_tasks,
    handle_task_lists,
)


routes = {
    "/api/task_lists": handle_api_task_lists,
    r"/api/task_lists/\d+": handle_api_tasks,
    "/api/register": handle_api_register,
    "/api/login": handle_api_login,
    r"/api/task_lists/\d+/delete": handle_api_delete_task_list,
    r"/api/task_lists/\d+/tasks/\d+/delete": handle_api_delete_task,
    r"/api/task_lists/\d+/edit": handle_api_edit_task_list,
    r"/api/task_lists/\d+/tasks/\d+/edit": handle_api_edit_task,
    "/task_lists": handle_task_lists,
    r"/task_lists/\d+": handle_tasks,
    "/register": handle_register,
    "/login": handle_login,
    r"/task_lists/\d+/delete": handle_delete_task_list,
    r"/task_lists/\d+/tasks/\d+/delete": handle_delete_task,
    r"/task_lists/\d+/edit": handle_edit_task_list,
    r"/task_lists/\d+/tasks/\d+/edit": handle_edit_task,
}

current_dir = os.path.dirname(os.path.abspath(__file__))
templates_dir = os.path.join(current_dir, "templates")


def find_handler(path: str, routes: dict) -> Callable | None:
    if path in routes:
        return routes[path]
    for route, handler in routes.items():
        if re.fullmatch(route, path):
            return handler
    return None


def app(environ: dict, start_response: Callable) -> [bytes]:
    path = environ["PATH_INFO"]
    handler = find_handler(path, routes)
    if handler:
        response = handler(environ)
    else:
        response = api_not_found() if path.startswith("/api/") else not_found()

    start_response(response["status"], response["headers"])
    return [response["body"]]
