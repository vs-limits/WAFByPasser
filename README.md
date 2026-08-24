# WAFByPasser

WAFByPasser 是一个面向授权安全测试与研究的 WAF Payload 生成、迭代、验证和知识沉淀平台。项目采用 FastAPI + React，支持语义变异、编码变换、交叉迭代、靶场验证及结果归档。

## 主要功能

- 语义迭代 Agent：理解 Payload 结构并生成语义等价变体
- 编码迭代 Agent：组合可逆编码与混淆策略
- 检验 Agent：在已配置靶场中执行验证并归档结果
- 知识库管理 Agent：提取、分类、泛化和沉淀绕过技巧
- Payload、候选池、迭代池、报告和验证队列管理
- 支持命令注入、SQL 注入、XSS、文件上传和 Log4j 场景

## 项目结构

```text
WAFByPasser/
├── backend/
│   ├── src/app/
│   │   ├── semantic_agent/
│   │   ├── encoding_agent/
│   │   ├── verification_agent/
│   │   └── knowledge_base_agent/
│   ├── scripts/
│   ├── seeds/
│   └── tests/
├── frontend/                 # React + Vite 管理界面
├── config/.env.example      # 配置模板
├── data/                    # 本地数据库与运行数据（不提交）
└── docs/                    # 设计与使用文档
```

## 快速启动

环境要求：Python 3.11+、Node.js 20+。

```powershell
git clone https://github.com/vs-limits/WAFByPasser.git
cd WAFByPasser

# 后端依赖与配置
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
Copy-Item config\.env.example config\.env

# 启动后端
$env:PYTHONPATH="backend\src"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

另开一个终端启动前端：

```powershell
cd WAFByPasser\frontend
npm install
npm run dev
```

- 前端：http://127.0.0.1:5184
- API 文档：http://127.0.0.1:8000/docs

如需浏览器自动化验证，请额外执行：

```powershell
playwright install chromium
```

## 配置

复制 `config/.env.example` 为 `config/.env`，至少填写 OpenAI 兼容的 `LLM_BASEURL`、`LLM_APIKEY`、`LLM_MODEL` 和 `LLM_PROVIDER`。靶场、检验并发及 OOB 监听配置均为可选项。

运行数据默认保存在 `data/waf_bypasser.db`。`.env`、数据库、日志和构建产物已由 `.gitignore` 排除。

知识库手法的全量版本化快照位于 `backend/seeds/knowledge_base_techniques.md` 和
`backend/seeds/knowledge_base_techniques.json`。本地知识库更新后可重新导出：

```powershell
python backend/scripts/export_knowledge_base.py
```

## 测试与构建

```powershell
$env:PYTHONPATH="backend\src"
python -m pytest backend\tests -q
npm --prefix frontend run build
```

## 使用声明

本项目仅用于已获授权的安全测试、教学和防御研究。请勿用于未经授权的系统或网络。
