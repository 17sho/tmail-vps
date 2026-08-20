# Google IMAP 接码网站（Flask）

## 功能
- 用户页面输入目标邮箱，查看该邮箱收到的邮件列表，并可点开查看邮件详情。
- 管理员后台可修改 IMAP 地址、端口、账号、密码、搜索范围等配置。
- 管理员后台支持一行格式快速导入：`名称|邮箱|密码|IMAP地址|端口`

## 目录
- `app.py`: Flask 主程序
- `templates/`: 页面模板
- `static/style.css`: 样式
- `data/config.json`: IMAP 配置（启动后自动生成）

## 运行步骤
1. 安装依赖
   ```powershell
   pip install -r requirements.txt
   ```
2. 设置管理员密码（可选，默认 `admin123`）
   ```powershell
   $env:ADMIN_PASSWORD="你的管理员密码"
   ```
3. 启动
   ```powershell
   python app.py
   ```
4. 打开页面
   - 用户页: `http://127.0.0.1:5000/`
   - 管理页: `http://127.0.0.1:5000/admin`

## Google 邮箱配置说明
- IMAP 地址: `imap.gmail.com`
- 端口: `993`
- SSL: 开启
- 账号: 你的 Gmail 地址
- 密码: 建议使用 Google App Password（需先启用两步验证）
- 一行导入示例: `gmail1|qq210300514@gmail.com|zntyupdjftyxvecv|imap.gmail.com|993`

## 注意
- 请仅用于你有权限管理的邮箱和业务场景。
- 当前演示把配置保存在本地 `data/config.json`，生产环境建议使用加密存储和更严格鉴权。
