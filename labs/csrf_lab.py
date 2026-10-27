"""
CSRF 靶场 —— 漏洞代码
======================
漏洞位置：do_transfer() 只校验了登录态（current_user），
完全没有校验请求携带的 CSRF token 是否与 expected_token 一致，
攻击者可伪造表单让已登录用户"被转账"。

修复方法：取消下方注释，转账前校验 token：
    if token != expected_token:
        return {"ok": False, "msg": "CSRF token 校验失败"}
"""
from db import get_conn


def do_transfer(current_user, to, amount, token, expected_token):
    """执行转账。

    current_user:   当前登录用户名
    to:             收款账户名
    amount:         转账金额
    token:          表单携带的 csrf_token
    expected_token: session 中保存的正确 csrf_token

    ============ 漏洞：完全忽略了 token 参数 ============
    """
    if current_user is None:
        return {"ok": False, "msg": "未登录"}

    # ↓↓↓ 修复：取消下面三行注释即可校验 CSRF token ↓↓↓
    # if token != expected_token:
    #     return {"ok": False, "msg": "CSRF token 校验失败，请求被拒绝"}

    try:
        amount = int(amount)
    except (TypeError, ValueError):
        return {"ok": False, "msg": "金额非法"}

    if amount <= 0:
        return {"ok": False, "msg": "金额必须大于 0"}

    conn = get_conn()
    cur = conn.cursor()

    cur.execute("SELECT id, balance FROM accounts WHERE name = ?", (current_user,))
    payer = cur.fetchone()
    if payer is None:
        conn.close()
        return {"ok": False, "msg": "付款账户不存在"}

    cur.execute("SELECT id FROM accounts WHERE name = ?", (to,))
    payee = cur.fetchone()
    if payee is None:
        conn.close()
        return {"ok": False, "msg": "收款账户不存在"}

    if payer["balance"] < amount:
        conn.close()
        return {"ok": False, "msg": "余额不足"}

    cur.execute(
        "UPDATE accounts SET balance = balance - ? WHERE id = ?",
        (amount, payer["id"]),
    )
    cur.execute(
        "UPDATE accounts SET balance = balance + ? WHERE id = ?",
        (amount, payee["id"]),
    )
    conn.commit()
    conn.close()
    return {"ok": True, "msg": f"转账成功：{current_user} -> {to}，金额 {amount}"}


def get_balance(name):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT balance FROM accounts WHERE name = ?", (name,))
    row = cur.fetchone()
    conn.close()
    return row["balance"] if row else None
