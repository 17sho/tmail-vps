# TMail 邮箱取件与验证码查询系统 — VPS / Flask 版

多邮箱源 IMAP 邮件取件与验证码查询系统。用户输入目标收件地址即可查看最近邮件和验证码；管理员可统一管理邮箱源、查询规则、黑名单、临时链接、记录、性能与健康状态。

> 本仓库是 **VPS / Flask 版**。Cloudflare Workers / D1 版请访问：[17sho/tmail-cloudflare](https://github.com/17sho/tmail-cloudflare)。

## 双版本

| 版本 | 仓库 | 适用环境 |
|---|---|---|
| VPS / Flask | [17sho/tmail-vps](https://github.com/17sho/tmail-vps) | Linux VPS、Windows 或其他可运行 Python 的主机 |
| Cloudflare Workers / D1 | [17sho/tmail-cloudflare](https://github.com/17sho/tmail-cloudflare) | Cloudflare Workers 与 D1 |

两个版本的主要用户功能和后台操作基本一致，部署方式与数据存储不同。

## 支持的邮箱

后台内置以下 IMAP Provider 预设，并支持自定义 IMAP：

- Gmail / Google Workspace
- QQ 邮箱
- Outlook / Hotmail / Microsoft 365
- iCloud Mail
- 163 邮箱
- 126 邮箱
- 新浪邮箱
- Yahoo Mail
- Zoho Mail
- 自定义 IMAP 服务器

> 邮箱服务商必须允许 IMAP 登录。开启两步验证后，通常需要使用服务商生成的授权码或 App Password，而不是网页登录密码。

## 主要功能

- 多邮箱源统一管理和并发查询
- 邮箱源优先级、独立超时和连接测试
- 连续失败熔断、健康状态及性能统计
- 查询范围、返回数量和验证码提取规则
- 黑名单与查询记录管理
- 限时、限次临时查询链接
- 桌面固定侧栏、移动端抽屉式后台
- 主动查询计数；自动轮询不重复计数
- 管理员 Session 登录、CSRF 防护和密码修改

## 安装

需要 Python 3.11+：

```bash
git clone https://github.com/17sho/tmail-vps.git
cd tmail-vps
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp data/config.example.json data/config.json
export ADMIN_PASSWORD='请设置强密码'
export APP_SECRET_KEY='请设置随机长字符串'
python app.py
```

打开：

- 用户页：`http://127.0.0.1:5000/`
- 管理页：`http://127.0.0.1:5000/admin`

默认只应监听 `127.0.0.1`。局域网访问需改为 `HOST=0.0.0.0` 并放行端口；公网部署建议使用 Caddy/Nginx 反向代理 HTTPS，且必须设置强管理员密码。

## 邮箱源配置

部署后登录管理后台添加邮箱源。也可使用一行格式快速导入：

```text
名称|邮箱地址|授权码|IMAP地址|端口
```

示例中的邮箱和授权码应替换为你自己的有效凭据，切勿把正式凭据写入仓库。

## 验证

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## 安全说明

- `data/config.json` 可能包含邮箱授权码和管理员密码哈希，已被 `.gitignore` 排除。
- `data/view_logs.json` 包含查询记录，不应提交。
- 仓库只提供脱敏的 `data/config.example.json`。
- 仅用于你有权管理的邮箱和合法业务场景。
