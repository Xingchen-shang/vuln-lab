"""
SQL 注入靶场 —— 漏洞代码
==========================
漏洞位置：check_login() 使用字符串拼接构造 SQL 语句，
攻击者可通过构造用户名（如 admin' --）注释掉密码条件，从而绕过登录。

修复方法：把字符串拼接改为参数化查询（占位符 ?）：
    cur.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    )
"""
from db import get_conn


def check_login(username, password):
    """校验用户名密码，成功返回用户记录（sqlite3.Row），失败返回 None。

    ============ 漏洞：字符串拼接 SQL ============
    """
    conn = get_conn()
    cur = conn.cursor()
    # ↓↓↓ 危险写法：直接把用户输入拼进 SQL ↓↓↓
    sql = (
        "SELECT * FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    cur.execute(sql)
    row = cur.fetchone()
    conn.close()
    return row
