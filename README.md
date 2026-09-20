## How to Run

### Docker 启动（推荐）

```bash
# 构建并启动所有服务
docker-compose up --build -d

# 查看运行状态
docker-compose ps

# 查看日志
docker-compose logs -f

# 停止服务
docker-compose down
```

启动后访问：
- 前端：http://localhost:8081
- 后端API：http://localhost:8636

### 本地启动

**后端：**
```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

**前端：**
直接用浏览器打开 `frontend/index.html`，或使用任意静态服务器：
```bash
cd frontend
python -m http.server 8081
```

## Services

| 服务 | 端口 | 说明 |
|------|------|------|
| frontend | 8081 | Nginx静态文件服务 + API代理 |
| backend | 8636 | Flask API服务 |

## 测试账号

| 用户名 | 密码 |
|--------|------|
| admin | admin123 |
| user | user123 |
| test | test123 |

## 运行测试

```bash
cd backend
pip install -r requirements.txt
pytest -v
```

## 题目内容

做一个下载网站，要求：
- 有加载动画
- 有上传按钮
- 点击下载时进行身份验证
- 验证完成后自动跳转下载
- 使用Python后端
- 前端端口：8081
- 后端端口：8636
- 支持Docker部署（ARM和X86跨平台）

---

## 项目介绍

做一个下载网站要有加载动画和上传按钮并且点击下载的时候会有身份验证的网页完成后自动跳转要用Python制作完成后放在文件夹中并且搭建服务器

### 功能特性

- 📤 文件上传
- 📥 文件下载（需身份验证）
- 🔐 用户身份验证
- ⏳ 加载动画效果
- 🛡️ 传输审计与操作留痕（接收 / 取件 / 授权 / 删除 / 导出全链路）
- 📋 审计记录筛选、分页与勾选导出（CSV / JSON）
- 🐳 Docker一键部署

### 传输审计与操作留痕

访问首页右上角「传输审计」或直接打开 `audit.html`（需登录）：

- **全链路留痕**：文件接收（上传）、文件取件（登录下载）、分享取件（匿名访客）、
  身份授权（登录成功/失败）、创建/删除分享、审计文件导出，均写入 `audit_logs` 表
- **身份与对象对得上**：业务数据与审计记录在同一数据库事务内提交，记录包含操作者、
  操作者类型（登录用户/访客）、来源 IP、对象类型/ID/名称、结果与失败原因
- **稳定的历史顺序与总数**：审计表只追加，按记录 ID 倒序展示，筛选后总数与翻页互不影响
- **勾选导出审计文件**：支持跨页勾选并导出为 CSV（带 UTF-8 BOM，Excel 可直接打开）或 JSON；
  选择集与筛选视图按登录身份保存在浏览器本地
- **失败不丢进度**：空选择、导出中断（超时/断网）、文件生成失败、登录过期时均保留当前选择，
  页面内明确说明原因，可直接重试；重新进入页面后选择、筛选、页码、导出格式自动恢复
- **导出本身也留痕**：每次导出（无论成功失败）都会归档一条 `audit_export` 记录，
  含所选数量、实际生成数量与失败原因，形成「采集 → 归档 → 导出」闭环

审计相关接口（均需 Bearer Token）：

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/audit/logs` | GET | 分页查询，支持 `action` / `result` / `keyword` / `page` / `page_size` |
| `/api/audit/export` | POST | 导出所选记录，请求体 `{ids: [...], format: "csv"\|"json"}` |


### 文件上传安全策略

项目采用扩展名黑名单机制，禁止上传以下类型的文件：

`exe, sh, bat, cmd, ps1, py, php, jsp, cgi, pl`

为什么用黑名单而不是白名单？
- 白名单需要预先列出所有允许的格式，每次有新格式都要手动添加，维护成本高
- 作为下载站，用户上传的文件类型多样且不可预测，白名单容易漏掉合法格式
- 黑名单只需拦截少量危险的可执行文件类型（如脚本、二进制程序），防止服务器被上传恶意代码利用
- 配合文件大小限制（默认50MB），已经能满足基本的安全需求

### 技术栈

- 前端：HTML + CSS + JavaScript
- 后端：Python Flask
- 部署：Docker + Nginx
