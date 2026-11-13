import sqlite3

ALLOWED_TABLES = {"users": "users", "orders": "orders", "invoices": "invoices"}


def count_rows(conn: sqlite3.Connection, kind: str) -> int:
    table = ALLOWED_TABLES[kind]
    return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
