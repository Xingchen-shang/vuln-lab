"""数据库初始化与连接（SQLite，Python 标准库自带，无需额外安装）。"""
import os
import sqlite3

from flags import IDOR_FLAG

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vulnlab.db")


def get_conn():
    """获取数据库连接，每行返回 sqlite3.Row，可按列名取值。"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """建表 + 写入种子数据（幂等，可重复调用）。"""
    conn = get_conn()
    cur = conn.cursor()

    # SQL 注入靶场：用户表
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """
    )
    # 存储型 XSS 靶场：留言表
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author TEXT NOT NULL,
            content TEXT NOT NULL
        )
        """
    )
    # CSRF 靶场：账户表
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            balance INTEGER NOT NULL
        )
        """
    )
    # 暴力破解靶场：用户表（弱口令）
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS brute_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """
    )
    # IDOR 越权靶场：用户私密资料表
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            secret TEXT NOT NULL
        )
        """
    )

    # 种子数据
    cur.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()["c"] == 0:
        cur.execute(
            "INSERT INTO users (username, password) VALUES ('admin', 'SuperSecret!@#123')"
        )
        cur.execute(
            "INSERT INTO users (username, password) VALUES ('guest', 'guest')"
        )

    # 每次启动清空留言板：避免上一次测试的 XSS payload 长期残留，
    # 重启后得到的永远是干净靶场（留言记录为空）。
    cur.execute("DELETE FROM comments")

    cur.execute("SELECT COUNT(*) AS c FROM accounts")
    if cur.fetchone()["c"] == 0:
        cur.execute("INSERT INTO accounts (name, balance) VALUES ('alice', 100000)")
        cur.execute("INSERT INTO accounts (name, balance) VALUES ('hacker', 0)")

    cur.execute("SELECT COUNT(*) AS c FROM brute_users")
    if cur.fetchone()["c"] == 0:
        # 弱口令 123456，常见字典必含，可用 Burp Intruder 爆破
        cur.execute(
            "INSERT INTO brute_users (username, password) VALUES ('victim', '123456')"
        )

    cur.execute("SELECT COUNT(*) AS c FROM profiles")
    if cur.fetchone()["c"] == 0:
        cur.execute(
            "INSERT INTO profiles (name, secret) VALUES ('alice', 'alice 的私密资料：我喜欢猫。')"
        )
        # admin(id=2) 的 secret 存放 flag，越权访问即可拿到
        cur.execute(
            "INSERT INTO profiles (name, secret) VALUES ('admin', ?)", (IDOR_FLAG,)
        )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print("数据库初始化完成:", DB_PATH)
