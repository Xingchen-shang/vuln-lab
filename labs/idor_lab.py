"""
IDOR 越权靶场 —— 漏洞代码
==========================
漏洞位置：get_profile() 只按 id 查询资料，完全没有校验
"当前登录用户是否有权访问这个 id"，攻击者改 id 即可越权
查看他人私密资料。

修复方法：校验请求的 profile_id 必须等于当前登录用户的 id：
    if profile_id != current_user_id:
        return None  # 无权访问
"""
from db import get_conn


def get_profile(profile_id, current_user_id):
    """按 id 查询用户资料。

    profile_id:       请求要查看的资料 id
    current_user_id:  当前登录用户的 id（session 里保存）

    ============ 漏洞：完全忽略了 current_user_id ============
    """
    # ↓↓↓ 修复：取消下面三行注释即可校验归属 ↓↓↓
    # if profile_id != current_user_id:
    #     return None

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT name, secret FROM profiles WHERE id = ?", (profile_id,))
    row = cur.fetchone()
    conn.close()
    return row
