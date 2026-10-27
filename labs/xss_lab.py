"""
存储型 XSS 靶场 —— 漏洞代码
============================
漏洞位置：render_comments() 直接把用户留言内容拼进 HTML，未做 HTML 转义，
攻击者提交的 <script> 会被浏览器当作代码执行。

修复方法：对用户输入做 HTML 转义后再拼接：
    import html
    safe_author = html.escape(author)
    safe_content = html.escape(content)
"""
from db import get_conn


def add_comment(author, content):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO comments (author, content) VALUES (?, ?)", (author, content)
    )
    conn.commit()
    conn.close()


def get_comments():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT author, content FROM comments ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return rows


def render_comments(comments):
    """把留言列表渲染成 HTML。

    ============ 漏洞：未对用户输入做 HTML 转义 ============
    """
    parts = []
    for author, content in comments:
        # ↓↓↓ 危险写法：用户输入直接拼进 HTML ↓↓↓
        parts.append(
            f'<div class="comment"><strong>{author}</strong><p>{content}</p></div>'
        )
    return "".join(parts)
