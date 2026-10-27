"""漏洞教学靶场 —— Flask 应用入口

一个用于安全教学的最小化 Web 靶场，包含：
  1. SQL 注入 / 存储型 XSS / CSRF / 暴力破解 / IDOR 五个漏洞的原理讲解
  2. 五个可攻击的靶场（各自对应一个 flag）
  3. 网页端查看、在线修改源码以修复漏洞（保存后热重载生效）

⚠️ 本应用故意包含漏洞，仅供本地/授权环境教学使用，严禁部署到公网。
"""
import importlib
import os

from flask import (Flask, flash, make_response, redirect, render_template,
                   request, session, url_for)

from db import init_db
from flags import BRUTE_FLAG, CSRF_FLAG, IDOR_FLAG, SQLI_FLAG, XSS_FLAG
import labs.sqli_lab as sqli_lab
import labs.xss_lab as xss_lab
import labs.csrf_lab as csrf_lab
import labs.brute_lab as brute_lab
import labs.idor_lab as idor_lab

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.secret_key = "vuln-lab-teaching-only-secret"  # 仅本地教学用

# 五个靶场的源码文件（网页上可查看/编辑的就是这些真实文件）
LAB_FILES = {
    "sqli": os.path.join(BASE_DIR, "labs", "sqli_lab.py"),
    "xss": os.path.join(BASE_DIR, "labs", "xss_lab.py"),
    "csrf": os.path.join(BASE_DIR, "labs", "csrf_lab.py"),
    "brute": os.path.join(BASE_DIR, "labs", "brute_lab.py"),
    "idor": os.path.join(BASE_DIR, "labs", "idor_lab.py"),
}
LAB_MODULES = {
    "sqli": sqli_lab,
    "xss": xss_lab,
    "csrf": csrf_lab,
    "brute": brute_lab,
    "idor": idor_lab,
}
ORIGINAL_DIR = os.path.join(BASE_DIR, "lab_originals")

EXPLAIN_TEMPLATES = {
    "sqli": "explain_sqli.html",
    "xss": "explain_xss.html",
    "csrf": "explain_csrf.html",
    "brute": "explain_brute.html",
    "idor": "explain_idor.html",
}

# 靶场清单（总览页用）
LABS = [
    {"key": "sqli", "name": "SQL 注入", "desc": "登录接口拼接 SQL，绕过登录拿到 admin 权限", "route": "lab_sqli"},
    {"key": "xss", "name": "存储型 XSS", "desc": "留言板未转义，注入脚本窃取 Cookie", "route": "lab_xss"},
    {"key": "csrf", "name": "CSRF", "desc": "伪造转账请求，让已登录用户把钱转给攻击者", "route": "lab_csrf"},
    {"key": "brute", "name": "暴力破解", "desc": "登录接口无防护，爆破弱口令", "route": "lab_brute"},
    {"key": "idor", "name": "IDOR 越权", "desc": "只改一个 id，越权查看他人私密资料", "route": "lab_idor"},
]
LAB_NAMES = {lab["key"]: lab["name"] for lab in LABS}
ALL_FLAGS = {
    "sqli": SQLI_FLAG,
    "xss": XSS_FLAG,
    "csrf": CSRF_FLAG,
    "brute": BRUTE_FLAG,
    "idor": IDOR_FLAG,
}


@app.route("/")
def index():
    solved = session.get("solved", [])
    return render_template("index.html", labs=LABS, solved=solved)


@app.route("/hints")
def hints():
    return render_template("hints.html")


@app.route("/submit_flag", methods=["POST"])
def submit_flag():
    flag = (request.form.get("flag") or "").strip()
    lab = (request.form.get("lab") or "").strip()
    solved = set(session.get("solved", []))

    if lab not in ALL_FLAGS:
        flash("❌ 未知的靶场", "error")
        return redirect(url_for("index"))

    name = LAB_NAMES[lab]
    if flag != ALL_FLAGS[lab]:
        flash(f"❌ 这不是「{name}」的 flag，再检查一下", "error")
        return redirect(url_for("index"))

    if lab in solved:
        flash(f"这个靶场你已经通过了：{name}", "ok")
    else:
        solved.add(lab)
        session["solved"] = sorted(solved)
        flash(f"✅ 正确！获得「{name}」的 flag", "ok")
    return redirect(url_for("index"))


@app.route("/reset_progress")
def reset_progress():
    session.pop("solved", None)
    flash("已重置通关进度", "ok")
    return redirect(url_for("index"))


# ---------- 原理讲解 ----------
@app.route("/explain/<name>")
def explain(name):
    if name not in EXPLAIN_TEMPLATES:
        return redirect(url_for("index"))
    return render_template(EXPLAIN_TEMPLATES[name])


# ---------- ① SQL 注入靶场 ----------
@app.route("/lab/sqli", methods=["GET", "POST"])
def lab_sqli():
    result = None
    success = None
    flag = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = sqli_lab.check_login(username, password)
        if user:
            result = f"登录成功！欢迎你，{user['username']}"
            success = True
            if user["username"] == "admin":
                flag = SQLI_FLAG
        else:
            result = "用户名或密码错误"
            success = False
    return render_template("lab_sqli.html", result=result, success=success, flag=flag)


# ---------- ② 存储型 XSS 靶场 ----------
@app.route("/lab/xss", methods=["GET", "POST"])
def lab_xss():
    if request.method == "POST":
        author = request.form.get("author", "匿名")
        content = request.form.get("content", "")
        if content.strip():
            xss_lab.add_comment(author, content)
        return redirect(url_for("lab_xss"))

    comments = xss_lab.get_comments()
    rendered = xss_lab.render_comments(comments)
    resp = make_response(render_template("lab_xss.html", rendered=rendered))
    # flag 放在未开启 HttpOnly 的 Cookie 中，模拟可被 XSS 窃取的会话令牌
    resp.set_cookie("xss_flag", XSS_FLAG, httponly=False)
    return resp


# ---------- ③ CSRF 靶场 ----------
@app.route("/lab/csrf", methods=["GET", "POST"])
def lab_csrf():
    if request.method == "POST" and request.form.get("action") == "login":
        name = request.form.get("name", "")
        session["csrf_user"] = name
        session["csrf_token"] = os.urandom(16).hex()
        return redirect(url_for("lab_csrf"))

    user = session.get("csrf_user")
    balance = None
    flag = None
    if user:
        balance = csrf_lab.get_balance(user)
        if user == "hacker" and balance is not None and balance > 0:
            flag = CSRF_FLAG
    return render_template("lab_csrf.html", user=user, balance=balance, flag=flag)


@app.route("/csrf/transfer", methods=["POST"])
def csrf_transfer():
    user = session.get("csrf_user")
    result = csrf_lab.do_transfer(
        user,
        request.form.get("to"),
        request.form.get("amount"),
        request.form.get("csrf_token", ""),
        session.get("csrf_token"),
    )
    flash(f"[{'成功' if result['ok'] else '失败'}] {result['msg']}",
          "ok" if result["ok"] else "error")
    return redirect(url_for("lab_csrf"))


@app.route("/csrf/logout")
def csrf_logout():
    session.pop("csrf_user", None)
    session.pop("csrf_token", None)
    return redirect(url_for("lab_csrf"))


@app.route("/lab/csrf/attack")
def lab_csrf_attack():
    return render_template("lab_csrf_attack.html")


# ---------- ④ 暴力破解靶场 ----------
@app.route("/lab/brute", methods=["GET", "POST"])
def lab_brute():
    result = None
    flag = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        user = brute_lab.check_login(username, password)
        if user == "LOCKED":
            result = "账号已锁定，请稍后再试"
        elif user:
            result = f"登录成功！欢迎你，{user['username']}"
            flag = BRUTE_FLAG
        else:
            result = "用户名或密码错误"
    return render_template("lab_brute.html", result=result, flag=flag)


# ---------- ⑤ IDOR 越权靶场 ----------
@app.route("/lab/idor", methods=["GET", "POST"])
def lab_idor():
    if request.method == "POST" and request.form.get("action") == "login":
        session["idor_user_id"] = 1  # alice 的 id
        session["idor_user_name"] = "alice"
        return redirect(url_for("lab_idor"))

    user_id = session.get("idor_user_id")
    user_name = session.get("idor_user_name")
    return render_template("lab_idor.html", user_name=user_name, user_id=user_id)


@app.route("/idor/profile")
def idor_profile():
    profile_id = request.args.get("id", type=int)
    current_user_id = session.get("idor_user_id")
    if current_user_id is None:
        return render_template("idor_profile.html", profile=None, is_flag=False,
                               flag=None, not_logged_in=True)
    profile = idor_lab.get_profile(profile_id, current_user_id)
    if profile is None:
        return render_template("idor_profile.html", profile=None, is_flag=False,
                               flag=None)
    is_flag = profile["secret"] == IDOR_FLAG
    return render_template("idor_profile.html", profile=profile, is_flag=is_flag,
                           flag=IDOR_FLAG)


@app.route("/idor/logout")
def idor_logout():
    session.pop("idor_user_id", None)
    session.pop("idor_user_name", None)
    return redirect(url_for("lab_idor"))


# ---------- 源码查看与在线修复 ----------
@app.route("/source")
def source_index():
    return render_template("source.html", name=None, code=None)


@app.route("/source/<name>")
def source_view(name):
    if name not in LAB_FILES:
        return redirect(url_for("source_index"))
    with open(LAB_FILES[name], "r", encoding="utf-8") as f:
        code = f.read()
    return render_template("source.html", name=name, code=code)


@app.route("/source/<name>/save", methods=["POST"])
def source_save(name):
    if name not in LAB_FILES:
        return redirect(url_for("source_index"))
    code = request.form.get("code", "")
    with open(LAB_FILES[name], "w", encoding="utf-8") as f:
        f.write(code)
    try:
        importlib.reload(LAB_MODULES[name])
        flash("源码已保存并热重载生效，可回到靶场验证修复", "ok")
    except Exception as e:  # noqa: BLE001 —— 用户可能写出语法错误
        flash(f"文件已保存，但重载失败（可能存在语法错误）：{e}", "error")
    return redirect(url_for("source_view", name=name))


@app.route("/source/<name>/reset", methods=["POST"])
def source_reset(name):
    if name not in LAB_FILES:
        return redirect(url_for("source_index"))
    original = os.path.join(ORIGINAL_DIR, os.path.basename(LAB_FILES[name]))
    with open(original, "r", encoding="utf-8") as f:
        code = f.read()
    with open(LAB_FILES[name], "w", encoding="utf-8") as f:
        f.write(code)
    importlib.reload(LAB_MODULES[name])
    flash("已恢复原始漏洞代码", "ok")
    return redirect(url_for("source_view", name=name))


init_db()

if __name__ == "__main__":
    # debug 便于本地排错；use_reloader=False 避免与网页源码编辑器的热重载冲突
    # 监听 0.0.0.0 是为了能用本机局域网 IP 访问（浏览器不会对非回环地址绕过代理，方便 Burp 抓包）
    # ⚠️ 本应用故意含漏洞，不要部署到公网；仅在可信的本地/局域网环境使用
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)
