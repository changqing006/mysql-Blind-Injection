# mysql-Blind-Injection

## SQL 盲注工具

### 一句话概括

> MySQL 聚焦的 SQL 盲注自动化工具，支持布尔盲注和时间盲注，自动检测注入点，二分法逐字符爆破数据库/表/字段/数据，ThreadPoolExecutor 并发加速，JSON 断点续传。

### 快速开始

```bash

# 自动检测 + 爆破（POST 场景）
python sqli_blind.py 
    -u http://127.0.0.1/sqli-labs/Less-16/ 
    --data "uname=*&passwd=1&submit=Submit"

# GET 时间盲注 + 4 线程并发
python sqli_blind.py 
    -u http://target.com/page.php 
    --data "id=*" --method GET -t T --threads 4

# 手动指定闭合方式 + 断点续传
python sqli_blind.py 
    -u http://target.com/login.php 
    --data "user=*&pass=1" 
    --prefix "admin')" --suffix "#" --resume
```

### 参数说明

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-u, --url` | 必填 | 目标 URL，可用 `*` 标记注入点 |
| `--data` | `None` | 请求数据，用 `*` 标记注入点，如 `"uname=*&passwd=1"` |
| `--method` | `POST` | `GET` 或 `POST` |
| `-t, --technique` | `B` | `B`=布尔盲注，`T`=时间盲注，`BT`=组合 |
| `--prefix` | `'` | 注入前缀（闭合引号/括号） |
| `--suffix` | `-- ` | 注入后缀（注释符） |
| `--flag` | 无 | 布尔盲注成功标志字符串（不填自动校准） |
| `--time-sec` | `2.0` | 时间盲注 SLEEP 秒数 |
| `--max-len` | `30` | 爆破名称最大长度 |
| `--threads` | `1` | 并发线程数（多线程加速表/字段/数据爆破） |
| `--rows` | `3` | 每列获取的数据行数 |
| `--cookie` | 无 | Cookie 字符串 |
| `--proxy` | 无 | 代理地址，如 `http://127.0.0.1:10809` |
| `--output` | `data` | 结果输出目录 |
| `--resume` | 否 | 从上次中断恢复（读取 `sqli_progress.json`） |
| `-v, --verbose` | 否 | DEBUG 级别日志 |

### 工作流程

```
自动检测注入点（~112 次探测）
  ├── 14 种闭合组合 × 2 种 HTTP 方法
  ├── 布尔检测: 比较 OR 1=1 / AND 1=2 响应差异
  └── 时间检测: 分别用 AND/OR 连接词测试 IF(1=1, SLEEP, 0)
       ↓
爆破当前数据库名 → 选择数据库 → 爆破表名（并发）→ 爆破字段名（并发）
       ↓
爆破数据行（并发）→ 导出 sqli_results.json
```

### 核心技术

**布尔盲注 — 无 flag 自动校准**

不依赖用户指定的标志字符串，自动发送 `1=1` 和 `1=2` 建立真/假响应长度基准。差异 ≤10 字节时自动降级为时间盲注。

**时间盲注 — AND/OR 连接词自动适配**

关键设计：检测时用 `IF(1=1, SLEEP, 0)` 而非 `(SELECT SLEEP)` —— 后者作为子查询会被 MySQL 优化器预求值，绕过短路逻辑，造成 AND/OR 都检测通过的假阳性。

**二分法爆破 — O(log₂N) 复杂度**

95 个可打印 ASCII 字符，每次探测砍掉一半搜索空间，最多 7 次请求确定一个字符（线性需 95 次，提速 ~13.5 倍）。

**并发爆破 — 名称级别并行**

不同表名/字段名/数据行互不依赖，用 `ThreadPoolExecutor` 并行爆破。同一名称内部的字符之间有依赖，保持串行。
