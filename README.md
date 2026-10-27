# Web 漏洞教学靶场（Vulnerable Web Lab）

一个用于**安全教学**的极简 Web 靶场，用 Python + Flask 开发，包含：

1. **原理讲解**：SQL 注入、存储型 XSS、CSRF、暴力破解、IDOR 越权五个常见漏洞的原理、成因、危害与防御。
2. **靶场实战**：五个可攻击的靶场，分别对应一个 flag。
3. **源码修复**：网页端查看并在线修改真实漏洞源码，保存后立即生效。

> ⚠️ **免责声明**：本项目**故意包含漏洞**，仅供本地学习、授权渗透测试环境使用。
> **严禁部署到公网或用于任何非法用途**，由此产生的一切后果由使用者自行承担。

---

## 快速开始

```bash
# 1. 创建虚拟环境（可选但推荐）
python -m venv venv

# Windows 激活
venv\Scripts\activate
# macOS / Linux 激活
source venv/bin/activate

# 2. 安装依赖
pip install -r requirements.txt

# 3. 运行（首次运行会自动初始化 SQLite 数据库）
python app.py

# 4. 浏览器打开
#    http://127.0.0.1:5000
```

> 依赖极简：仅需 `Flask`，数据库使用 Python 标准库自带的 `sqlite3`，无需额外安装。

---

## 使用流程

1. 打开首页（总览页 `/`），可以看到 5 个靶场的简介、**「搭建靶场」**按钮，以及每个靶场卡片下方的 **flag 提交框**。
2. 点「搭建靶场」会在**新标签页**打开对应靶场（靶场页面本身**不提供任何提示**）。
3. 卡住时，去独立的 **「破解提示」** 页面（`/hints`）查看所有靶场的破解思路和 payload。
4. 拿到 flag 后回到首页，在**该靶场自己的卡片下方**提交验证；通过后卡片会标记「✅ 已通过」并隐藏提交框，点底部「重置进度」可清空全部进度。

> 说明：每次**重启服务**都会清空 XSS 靶场的留言板（防止上一次测试的 `<script>` 脚本长期残留、每次打开都弹窗）。运行期间你提交的留言会保留，刷新靶场即可验证存储型 XSS；重启后靶场自动恢复干净。

---

## 五个漏洞与 flag

| 漏洞 | 靶场入口 | 攻击方法 | Flag |
|---|---|---|---|
| SQL 注入 | `/lab/sqli` | 用户名填 `admin' --` 绕过登录 | `FLAG{sql1_1nj3ct10n_bypass}` |
| 存储型 XSS | `/lab/xss` | 留言提交 `<script>alert(document.cookie)</script>` | `FLAG{st0red_xss_c00kie}` |
| CSRF | `/lab/csrf` | 以 alice 登录后打开攻击页面，伪造转账给 hacker | `FLAG{csrf_f0rged_transfer}` |
| 暴力破解 | `/lab/brute` | 用 Burp Intruder 爆破 `victim` 的弱口令 | `FLAG{brut3_f0rc3_w34k_pwd}` |
| IDOR 越权 | `/lab/idor` | 以 alice 登录，用 Burp 把 `id=1` 改成 `id=2` | `FLAG{1d0r_h0r1z0nt4l_3sc4l4t10n}` |

> 上表是直接 URL；正常流程是从首页点「搭建靶场」在新标签页打开，靶场页不含任何提示。

### 详细攻击步骤

**① SQL 注入**
1. 打开「SQL 注入靶场」。
2. 用户名输入 `admin' --`，密码随意。
3. 登录成功，得到 flag。

**② 存储型 XSS**
1. 打开「存储型 XSS 靶场」。
2. 留言内容输入 `<script>alert(document.cookie)</script>` 并提交。
3. 脚本执行，弹窗中即可看到 Cookie 里的 `xss_flag`。

**③ CSRF**
1. 打开「CSRF 靶场」，登录为 `alice`（受害者）。
2. 保持登录，点击「打开攻击页面」，隐藏表单自动把钱转给 `hacker`。
3. 退出登录，改为登录 `hacker`，余额 > 0 即得到 flag。

**④ 暴力破解**
1. 打开「暴力破解靶场」，已知用户名为 `victim`。
2. 用 Burp Suite 拦截登录请求，Send to Intruder，对 `password` 字段挂弱口令字典爆破。
3. 找出响应长度不同的那一条，即为正确密码，登录得到 flag。

**⑤ IDOR 越权**
1. 打开「IDOR 越权靶场」，以 `alice`（id=1）登录。
2. 点「查看我的资料」，用 Burp 拦截请求，把 `id=1` 改成 `id=2`。
3. 发送后越权看到 admin（id=2）的私密资料，即 flag。

---

## 如何"修复漏洞"

在「源码修复」页面选择对应的 `labs/*.py` 文件，按注释提示修改后点「保存并生效」，改动会**热重载立即生效**，回到靶场即可验证攻击已被拦截。点「恢复原始漏洞代码」可还原。

- **SQL 注入**：字符串拼接 → 参数化查询。
- **存储型 XSS**：对用户输入做 `html.escape()` 转义。
- **CSRF**：转账前校验 `token` 与 `expected_token`。
- **暴力破解**：加登录失败次数限制 / 账号锁定 / 验证码 / 限速。
- **IDOR**：校验请求的 `profile_id` 必须等于当前登录用户的 `current_user_id`。

---

## 冒烟测试（可选）

无需启动服务器，用 Flask 测试客户端验证五个靶场都能拿到 flag：

```bash
python smoke_test.py
```

---

## 项目结构

```
vuln-lab/
├── app.py                 # 入口与路由
├── db.py                  # SQLite 建表与种子数据
├── flags.py               # 五个 flag（不出现在源码编辑器里）
├── requirements.txt
├── smoke_test.py          # 冒烟测试
├── labs/                  # 五个靶场的漏洞代码（网页上可查看/编辑）
│   ├── sqli_lab.py
│   ├── xss_lab.py
│   ├── csrf_lab.py
│   ├── brute_lab.py
│   └── idor_lab.py
├── lab_originals/         # 漏洞代码的原始备份（用于"恢复"）
├── templates/             # 页面模板
├── static/                # 样式
└── README.md
```

---

## 技术栈

- Python 3.9+
- Flask 3.x
- SQLite（标准库 `sqlite3`）

## 开源协议

MIT License，详见 [LICENSE](LICENSE)。
