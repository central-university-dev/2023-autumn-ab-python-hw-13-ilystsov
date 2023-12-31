import uuid
from os import environ, path
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


def execute(query, params=None, fetch=False):
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

    def create_users_table(self):
        query = """
            CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
            )
            """
        execute(query)

    def create_sessions_table(self):
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
    def fetch_task_lists(self, user_id, get_name=False, list_id=None):
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

    def fetch_tasks(self, list_id):
        query = "SELECT name, id FROM tasks WHERE list_id = %s"
        return execute(query, (list_id,), fetch=True)

    def fetch_user_by_username(self, username):
        query = """
            SELECT id, username, password, role
            FROM users WHERE username = %s
            """
        return execute(query, (username,), fetch=True)

    def fetch_session(self, session_id):
        query = """
            SELECT user_id, csrf_token, created_at
            FROM sessions WHERE session_id = %s
            """
        return execute(query, (session_id,), fetch=True)

    def fetch_list_owner_id(self, list_id):
        query = "SELECT user_id FROM task_lists WHERE id = %s"
        return execute(query, (list_id,), fetch=True)

    def fetch_all_task_lists(self):
        query = "SELECT id, user_id, name FROM task_lists"
        return execute(query, fetch=True)

    def fetch_user_role(self, user_id):
        query = "SELECT role FROM users WHERE id = %s"
        result = execute(query, (user_id,), fetch=True)
        return result[0][0] if result else None

    def fetch_all_tasks(self):
        query = """
            SELECT tasks.name, task_lists.user_id, tasks.id
            FROM tasks JOIN task_lists ON tasks.list_id = task_lists.id
            """
        return execute(query, fetch=True)


class InsertData:
    def insert_task_lists(self, name, user_id):
        query = "INSERT INTO task_lists (name, user_id) VALUES (%s, %s)"
        execute(query, (name, user_id))

    def insert_tasks(self, name, list_id):
        query = "INSERT INTO tasks (name, list_id) VALUES (%s, %s)"
        execute(query, (name, list_id))

    def insert_user(self, username, password, role):
        query = (
            "INSERT INTO users (username, password, role) VALUES (%s, %s, %s)"
        )
        execute(query, (username, password, role))

    def insert_session(self, user_id, csrf_token):
        query = """
            INSERT INTO sessions (session_id, user_id, csrf_token)
            VALUES (%s, %s, %s)
            """
        session_id = str(uuid.uuid4())
        execute(query, (session_id, user_id, csrf_token))
        return session_id


class DeleteData:  # можно только одно id
    def delete_task_list(self, list_id, user_id):
        query = "DELETE FROM task_lists WHERE id = %s AND user_id = %s"
        execute(query, (list_id, user_id))

    def delete_task(self, task_id, user_id):
        query = """
        DELETE FROM tasks WHERE id = %s AND list_id IN
        (SELECT id FROM task_lists WHERE user_id = %s)
        """
        execute(query, (task_id, user_id))


class UpdateData:
    def update_task_list(self, list_id, user_id, new_name):
        query = (
            "UPDATE task_lists SET name = %s WHERE id = %s AND user_id = %s"
        )
        execute(query, (new_name, list_id, user_id))

    def update_task(self, task_id, list_id, user_id, new_name):
        query = """
        UPDATE tasks SET name = %s WHERE id = %s AND list_id = %s
        AND list_id IN (SELECT id FROM task_lists WHERE user_id = %s)
        """
        execute(query, (new_name, task_id, list_id, user_id))
