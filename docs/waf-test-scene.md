# WAF 测试场

测试场配置统一保存在 `config/.env`，敏感认证信息不会返回前端或写入测试记录。

## DVWA + 雷池 WAF

配置 `WAF_DVWA_BASE_URL`、`WAF_DVWA_USERNAME` 和 `WAF_DVWA_PASSWORD`。后端只允许访问该固定同源地址，并在自己的 DVWA 会话中设置 Low 安全等级。

首次启用后在后端环境执行：

```powershell
pip install -r backend/requirements.txt
playwright install chromium
```

在工作台的“WAF 测试场”执行预检。预检会登录 DVWA、要求 security 为 **Low**，并验证标准命令注入、SQL 注入和反射型 XSS 表单。预检失败时不会发送候选 Payload。

每个候选需要在详情中主动点击“发送到 WAF 测试场”；来源靶场仅作为库内分类，命令注入、SQL 注入和 XSS 候选都会发送到当前唯一配置的 DVWA + 雷池测试场。系统不改变候选的人工成功/失败状态。

## 腾讯云 WAF

配置 `TENCENT_WAF_IP` 和 `TENCENT_WAF_HOST`。直接测试请求发送到配置 IP，并携带配置的 Host 头；前端不允许输入或覆盖任意目标地址。

新增测试场代码或修改 `DIRECT_WAF_TARGETS` 后必须重启 FastAPI。若前端显示“后端版本未更新”，说明 `127.0.0.1:8000` 仍在运行旧版接口，重启后端并刷新页面即可。
