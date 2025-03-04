import psycopg2 # type: ignore
from contextlib import contextmanager
from psycopg2.extras import RealDictCursor # type: ignore
from config.settings import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD

def get_connection_string():
    return f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    try:
        yield conn
    finally:
        conn.close()

@contextmanager
def get_db_cursor(commit=False):
    """Context manager for database cursors"""
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        try:
            yield cursor
            if commit:
                conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()

def execute_query(query, params=None, fetch=True, commit=True):
    """Execute a database query and return results if needed"""
    with get_db_cursor(commit=commit) as cursor:
        cursor.execute(query, params or {})
        if fetch:
            return cursor.fetchall()
        return None
