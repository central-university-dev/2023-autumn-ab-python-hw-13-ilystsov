import uuid
from datetime import datetime
from os import environ, path
from typing import Any

from dotenv import load_dotenv
from psycopg2 import pool

current_directory = path.dirname(path.realpath(__file__))
dotenv_path = path.join(current_directory, "..", ".env")
load_dotenv(dotenv_path=dotenv_path)


class ConnectionPool:
    _connection_pool = None
    _tables_initialized = False

    @classmethod
    def _initialize_tables(cls):
        if not cls._tables_initialized:
            cls._tables_initialized = True
            CreateTable().create_users_table()
            CreateTable().create_task_lists_table()
            CreateTable().create_tasks_table()
            CreateTable().create_sessions_table()

    @classmethod
    def get_pool(cls):
        if cls._connection_pool is None:
            connection_pool = pool.SimpleConnectionPool(
                minconn=1,
                maxconn=10,
                database=environ.get("POSTGRES_DB"),
                user=environ.get("POSTGRES_USER"),
                password=environ.get("POSTGRES_PASSWORD"),
                host="db",
                port=5432,
            )
            cls._connection_pool = connection_pool
        cls._initialize_tables()
        return cls._connection_pool


def execute(
    query: str, params: tuple[Any, ...] | None = None, fetch: bool = False
) -> list[tuple[Any, ...]] | None:
    result = None
    connection_pool = ConnectionPool.get_pool()
    conn = connection_pool.getconn()
    with conn.cursor() as cur:
        cur.execute(query, params)
        if fetch:
            result = cur.fetchall()
    conn.commit()
    connection_pool.putconn(conn)
    return result


class CreateTable:
    def create_task_lists_table(self) -> None:
        query = """
            CREATE TABLE IF NOT EXISTS task_lists (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            user_id INT REFERENCES users(id) ON DELETE CASCADE NOT NULL
            )
            """
        execute(query)

    def create_tasks_table(self) -> None:
        query = """
            CREATE TABLE IF NOT EXISTS tasks (
            id SERIAL PRIMARY KEY,
            list_id INT REFERENCES task_lists(id) ON DELETE CASCADE NOT NULL,
            name TEXT NOT NULL
            )
            """
        execute(query)

    def create_users_table(self) -> None:
        query = """
            CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
            )
            """
        execute(query)

    def create_sessions_table(self) -> None:
        query = """
           CREATE TABLE IF NOT EXISTS sessions (
           session_id TEXT PRIMARY KEY,
           user_id INTEGER REFERENCES users(id),
           csrf_token TEXT,
           created_at TIMESTAMP WITHOUT TIME ZONE DEFAULT
           (NOW() AT TIME ZONE 'UTC')
           )
           """
        execute(query)


class FetchData:
    def fetch_task_lists(
        self, user_id: int, get_name: bool = False, list_id: int | None = None
    ) -> list[tuple[Any, ...]] | None:
        if not get_name:
            params = (user_id,)
            query = (
                "SELECT id, user_id, name FROM task_lists WHERE user_id = %s"
            )
        elif get_name and id is not None:
            params = (list_id, user_id)
            query = (
                "SELECT name FROM task_lists WHERE id = %s AND user_id = %s"
            )
        else:
            return
        return execute(query, params, fetch=True)

    def fetch_tasks(self, list_id: int) -> list[tuple[str, int]] | None:
        query = "SELECT name, id FROM tasks WHERE list_id = %s"
        return execute(query, (list_id,), fetch=True)

    def fetch_user_by_username(
        self, username: str
    ) -> list[tuple[int, str, str, str]] | None:
        query = """
            SELECT id, username, password, role
            FROM users WHERE username = %s
            """
        return execute(query, (username,), fetch=True)

    def fetch_session(
        self, session_id: str
    ) -> list[tuple[int, str, datetime]] | None:
        query = """
            SELECT user_id, csrf_token, created_at
            FROM sessions WHERE session_id = %s
            """
        return execute(query, (session_id,), fetch=True)

    def fetch_list_owner_id(self, list_id: int) -> list[tuple[int]] | None:
        query = "SELECT user_id FROM task_lists WHERE id = %s"
        return execute(query, (list_id,), fetch=True)

    def fetch_all_task_lists(self) -> list[tuple[int, int, str]] | None:
        query = "SELECT id, user_id, name FROM task_lists"
        return execute(query, fetch=True)

    def fetch_user_role(self, user_id: int) -> str | None:
        query = "SELECT role FROM users WHERE id = %s"
        result = execute(query, (user_id,), fetch=True)
        return result[0][0] if result else None

    def fetch_all_tasks(self) -> list[tuple[str, int, int]] | None:
        query = """
            SELECT tasks.name, task_lists.user_id, tasks.id
            FROM tasks JOIN task_lists ON tasks.list_id = task_lists.id
            """
        return execute(query, fetch=True)


class InsertData:
    def insert_task_lists(self, name: str, user_id: int) -> None:
        query = "INSERT INTO task_lists (name, user_id) VALUES (%s, %s)"
        execute(query, (name, user_id))

    def insert_tasks(self, name: str, list_id: int) -> None:
        query = "INSERT INTO tasks (name, list_id) VALUES (%s, %s)"
        execute(query, (name, list_id))

    def insert_user(self, username: str, password: str, role: str) -> None:
        query = (
            "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)"
        )
        execute(query, (username, password, role))

    def insert_session(self, user_id: int, csrf_token: str) -> str:
        query = """
            INSERT INTO sessions (session_id, user_id, csrf_token)
            VALUES (%s, %s, %s)
            """
        session_id = str(uuid.uuid4())
        execute(query, (session_id, user_id, csrf_token))
        return session_id


class DeleteData:
    def delete_task_list(self, list_id: int, user_id: int) -> None:
        query = "DELETE FROM task_lists WHERE id = %s AND user_id = %s"
        execute(query, (list_id, user_id))

    def delete_task(self, task_id: int, user_id: int) -> None:
        query = """
        DELETE FROM tasks WHERE id = %s AND list_id IN
        (SELECT id FROM task_lists WHERE user_id = %s)
        """
        execute(query, (task_id, user_id))


class UpdateData:
    def update_task_list(
        self, list_id: int, user_id: int, new_name: str
    ) -> None:
        query = (
            "UPDATE task_lists SET name = %s WHERE id = %s AND user_id = %s"
        )
        execute(query, (new_name, list_id, user_id))

    def update_task(
        self, task_id: int, list_id: int, user_id: int, new_name: str
    ) -> None:
        query = """
        UPDATE tasks SET name = %s WHERE id = %s AND list_id = %s
        AND list_id IN (SELECT id FROM task_lists WHERE user_id = %s)
        """
        execute(query, (new_name, task_id, list_id, user_id))
