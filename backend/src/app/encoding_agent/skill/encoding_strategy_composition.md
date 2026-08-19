# 编码策略与组合 Skill

仅从后端提供的 `allowed_encodings` 中选择策略。通用 URL、HTML 实体、Unicode、十六进制文本、Base64/Base64URL 可以按白名单组成一至两层链路。

## Shell 解释器级策略

当且仅当命令注入基础 Payload 可识别为“注入分隔符 + 直接命令名”时，可选择：

- `shell_printf_octal_command`：由 `printf` 解释八进制命令名；
- `shell_ansi_c_octal_command`：由 Bash ANSI-C 字符串解释八进制命令名。

这两种策略只允许单层，不得与通用编码链组合；说明必须写出解释器前提。SQL、XSS、文件上传不得选择 Shell 策略。
