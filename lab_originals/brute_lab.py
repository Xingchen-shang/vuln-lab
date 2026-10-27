"""
暴力破解靶场 —— 漏洞代码
==========================
漏洞位置：check_login() 没有任何防爆破措施——
没有登录失败次数限制、没有账号锁定、没有验证码、没有限速，
攻击者可用 Burp Suite 的 Intruder 无限尝试密码，爆破出弱口令。

修复方法（任选其一或组合）：
1. 失败次数限制 / 账号锁定：同一用户名连续失败 N 次后拒绝登录。
2. 登录失败延时：失败后 sleep 一小段时间，拖慢爆破。
3. 验证码：爆破时需额外识别验证码。
4. 限速：限制单 IP / 账号的请求频率。
"""
from db import get_conn


def check_login(username, password):
    """校验用户名密码，成功返回用户记录，失败返回 None。

    注意：本接口的 SQL 已参数化（不存在 SQL 注入），
    漏洞在于"对登录尝试没有任何防护"。
    """
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM brute_users WHERE username = ? AND password = ?",
        (username, password),
    )
    row = cur.fetchone()
    conn.close()
    return row
