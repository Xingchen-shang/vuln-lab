# 五个漏洞源码修复指南

> 对应项目「Web 漏洞教学靶场」。本指南教你如何在网页端修改 `labs/*.py` 源码，修复 **SQL 注入、存储型 XSS、CSRF、暴力破解、IDOR** 五个漏洞。

---

## 通用操作流程

1. 打开网站 → 首页 →「**源码修复**」→ 选择对应的 `labs/*.py` 文件。
2. 在文本框里按下方「修改后」的代码编辑，点「**💾 保存并生效**」。
3. 保存后代码会**热重载立即生效**，回到靶场用攻击 payload 复测。
4. 想重新演示漏洞，点「**↩️ 恢复原始漏洞代码**」一键还原。

> 判断标准：**同一个攻击 payload，修复前成功、修复后失败**，即说明修复生效；同时确认正常功能仍可用（避免"改坏了"被误当成"修好了"）。

---

## ① SQL 注入（`labs/sqli_lab.py`）

**漏洞点**：`check_login()` 用字符串拼接构造 SQL，用户输入能改变 SQL 结构。

**修改前（危险写法）**
```python
    # ↓↓↓ 危险写法：直接把用户输入拼进 SQL ↓↓↓
    sql = (
        "SELECT * FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )
    cur.execute(sql)
    row = cur.fetchone()
```

**修改后（参数化查询）**
```python
    cur.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    )
    row = cur.fetchone()
```

**验证**：回到 SQL 注入靶场，用 `admin' --` 登录 → 显示「用户名或密码错误」（注入被拦截）；再用 `guest / guest` 登录 → 仍能成功（正常功能未破坏）。

---

## ② 存储型 XSS（`labs/xss_lab.py`）

**漏洞点**：`render_comments()` 把用户留言直接拼进 HTML，未做转义。

**修改前（危险写法）**
```python
    parts = []
    for author, content in comments:
        # ↓↓↓ 危险写法：用户输入直接拼进 HTML ↓↓↓
        parts.append(
            f'<div class="comment"><strong>{author}</strong><p>{content}</p></div>'
        )
    return "".join(parts)
```

**修改后（HTML 转义）**

先在文件顶部 `from db import get_conn` 后面加一行 `import html`，再改函数体：
```python
    parts = []
    for author, content in comments:
        parts.append(
            f'<div class="comment"><strong>{html.escape(author)}</strong><p>{html.escape(content)}</p></div>'
        )
    return "".join(parts)
```

**验证**：回到留言板，之前注入的 `<script>alert(document.cookie)</script>` 会变成纯文本显示，不再弹窗。

---

## ③ CSRF（`labs/csrf_lab.py`）

**漏洞点**：`do_transfer()` 完全忽略了表单携带的 `token`，转账前未校验。

**修改前（校验被注释掉）**
```python
    # ↓↓↓ 修复：取消下面三行注释即可校验 CSRF token ↓↓↓
    # if token != expected_token:
    #     return {"ok": False, "msg": "CSRF token 校验失败，请求被拒绝"}
```

**修改后（取消注释，开启校验）**
```python
    if token != expected_token:
        return {"ok": False, "msg": "CSRF token 校验失败，请求被拒绝"}
```

**验证**：回到 CSRF 靶场，正常转账表单（自带 token）仍能成功；但打开「攻击页面」（不带 token）会被拒绝，钱不再被转给 hacker。

---

## ④ 暴力破解（`labs/brute_lab.py`）

**漏洞点**：`check_login()` 对登录尝试没有任何防护——无失败次数限制、无锁定、无验证码、无限速，可被 Burp Intruder 无限爆破。

**修改前（无任何防护）**
```python
from db import get_conn


def check_login(username, password):
    """校验用户名密码，成功返回用户记录，失败返回 None。"""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM brute_users WHERE username = ? AND password = ?",
        (username, password),
    )
    row = cur.fetchone()
    conn.close()
    return row
```

**修改后（失败次数限制 + 账号锁定 + 返回"已锁定"信号）**
```python
import time

from db import get_conn

# 记录每个用户名的失败状态：{username: [连续失败次数, 锁定到期时间]}
_state = {}

MAX_ATTEMPTS = 5      # 连续失败 5 次后锁定
LOCK_SECONDS = 60     # 锁定 60 秒


def check_login(username, password):
    """校验用户名密码。

    返回值：
      - 用户记录：登录成功
      - "LOCKED"：账号已锁定（网页会显示"账号已锁定，请稍后再试"）
      - None：用户名或密码错误
    """
    now = time.time()
    fails, lock_until = _state.get(username, [0, 0])

    # 修复：锁定期内直接拒绝，并返回"已锁定"信号
    if lock_until > now:
        return "LOCKED"
    # 锁定已到期，重置失败计数
    if lock_until != 0:
        fails = 0
        _state[username] = [0, 0]

    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM brute_users WHERE username = ? AND password = ?",
        (username, password),
    )
    row = cur.fetchone()
    conn.close()

    if row is None:
        fails += 1
        if fails >= MAX_ATTEMPTS:
            # 连续失败达到 5 次 → 锁定 60 秒
            _state[username] = [fails, now + LOCK_SECONDS]
        else:
            _state[username] = [fails, 0]
        # time.sleep(0.3)  # 可选：失败延时，进一步拖慢爆破
    else:
        _state.pop(username, None)   # 登录成功，清除失败记录
    return row
```

> 说明：`app.py` 里已经约定好——`check_login` 返回字符串 `"LOCKED"` 时，网页显示「账号已锁定，请稍后再试」。所以你只需要改 `brute_lab.py` 这一个文件，不用动其他文件。
>
> 其他可选修复方向：验证码、单 IP/账号限速、登录失败延时、强制强口令 + 多因素认证。

**验证**：连续输错 5 次密码后，第 6 次再提交，页面会提示「账号已锁定，请稍后再试」；等待 60 秒锁定到期后可重新尝试。同时，正常输入正确密码仍能登录（修复没有破坏正常功能）。

---

## ⑤ IDOR 越权（`labs/idor_lab.py`）

**漏洞点**：`get_profile()` 只按 `id` 查询资料，忽略了 `current_user_id`，未校验归属。

**修改前（校验被注释掉）**
```python
    # ↓↓↓ 修复：取消下面三行注释即可校验归属 ↓↓↓
    # if profile_id != current_user_id:
    #     return None
```

**修改后（取消注释，开启归属校验）**
```python
    if profile_id != current_user_id:
        return None
```

**验证**：以 alice 登录后，访问 `id=1` 仍能看到自己的资料；但用 Burp 把 `id` 改成 `2`（admin）时，返回「无权访问」，越权被阻断。

---

## 附：修复速查表

| 漏洞 | 文件 | 一句话修复 | 验证 payload |
|---|---|---|---|
| SQL 注入 | `sqli_lab.py` | 字符串拼接 → 参数化查询 `?` | `admin' --` 登录失败 |
| 存储型 XSS | `xss_lab.py` | 加 `html.escape()` 转义 | `<script>` 不再执行 |
| CSRF | `csrf_lab.py` | 取消注释 token 校验 | 攻击页面被拒绝 |
| 暴力破解 | `brute_lab.py` | 加失败次数限制/锁定 | 连错 5 次后提示「账号已锁定」 |
| IDOR | `idor_lab.py` | 取消注释归属校验 | `id=2` 返回无权访问 |
