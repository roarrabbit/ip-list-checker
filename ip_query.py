#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IP 黑白名单查询脚本

特性:
  - 基于本地 CSV 文件（黑名单.csv / 白名单.csv）进行查询
  - 精确匹配: 单 IP 相等 / 落在某个 CIDR 网段内
  - 模糊匹配: 按查询 IP 的前 2 段(/16, IPv6 /32) 与前 3 段(/24, IPv6 /48) 网段，
             检查名单中是否存在同网段条目（用于"同段相关"预警）
  - 同时支持 IPv4 与 IPv6
  - 支持单条 / 批量（文件 / 多行 stdin）查询
  - 可选: 支持向黑白名单追加录入（也可继续手动编辑 CSV，二者互不影响）

用法:
  # 【推荐】对话模式: 直接运行，多行逐个回车输入，空行回车执行查询
  python ip_query.py
      > 192.0.2.10
      > 198.51.100.7
      > 203.0.113.44
      >            <- 空行 + 回车 执行批量查询
  # 对话模式内命令: go 执行 | add 录入 | reload 重读CSV | clear 清屏 | help 帮助 | exit 退出
  # 查完后可选择: [a]全量追加黑名单 / [b]去重追加 / [c]不追加（管道/CLI query 不追问）

  # 命令行模式（也可用，但非必须）:
  # 查询（多 IP 空格分隔）
  python ip_query.py query 192.0.2.10 198.51.100.7 8.8.8.8
  # 从文件批量查询（每行一个 IP）
  python ip_query.py query -f ips.txt
  # 从管道多行输入
  cat ips.txt | python ip_query.py query
  # 结果同时写入文件
  python ip_query.py query -f ips.txt -o result.txt

  # 可选: 追加录入
  python ip_query.py add black 203.0.113.1
  python ip_query.py add white 203.0.113.0/28
  python ip_query.py add black -f newips.txt
"""
import argparse
import csv
import ipaddress
import os
import select
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BLACK_FILE = os.path.join(BASE_DIR, "黑名单.csv")
WHITE_FILE = os.path.join(BASE_DIR, "白名单.csv")

# 模糊匹配的网段长度: (前2段, 前3段)
V4_SEG = [16, 24]   # IPv4: /16, /24
V6_SEG = [32, 48]   # IPv6: /32, /48  (每段=16bit, 2段=32, 3段=48)


def clean_token(s):
    """清洗 IP 字符串: 去首尾空白、去混入的全角/半角逗号。"""
    if s is None:
        return ""
    s = s.strip()
    s = s.strip("，").strip(",").strip()
    return s


def load_list(path, ip_header_hint):
    """读取 CSV, 提取 IP 列, 解析为 ip_network 列表。
    返回 (entries, errors, warnings)
      entries: [{"raw": 原始串, "net": ip_network, "version": 4/6}, ...]
    """
    entries, errors, warnings = [], [], []
    if not os.path.exists(path):
        errors.append("文件不存在: %s" % path)
        return entries, errors, warnings

    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.reader(f))
    if not rows:
        return entries, errors, warnings

    header = rows[0]
    idx = None
    for i, h in enumerate(header):
        hh = clean_token(h)
        if ip_header_hint in hh:
            idx = i
            break
    if idx is None:
        idx = 1 if len(header) > 1 else 0
        warnings.append("未找到含 '%s' 的表头列, 回退使用第 %d 列作为 IP 列"
                        % (ip_header_hint, idx + 1))

    for lineno, row in enumerate(rows[1:], start=2):
        if not row or idx >= len(row):
            continue
        raw = clean_token(row[idx])
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as e:
            errors.append("第 %d 行无法解析 '%s': %s" % (lineno, raw, e))
            continue
        if net.version == 4 and net.prefixlen < 8:
            warnings.append("第 %d 行网段过宽 %s (/%d), 可能大量误命中, 请确认是否为笔误"
                            % (lineno, raw, net.prefixlen))
        if net.version == 6 and net.prefixlen < 32:
            warnings.append("第 %d 行 IPv6 网段过宽 %s (/%d)" % (lineno, raw, net.prefixlen))
        entries.append({"raw": raw, "net": net, "version": net.version})
    return entries, errors, warnings


def build_fuzzy_index(entries):
    """建立模糊索引: 前缀网络对象 -> 原始条目串列表。
    仅对 plen <= 该条目 prefixlen 的粒度建立（即取该条目所在的前2/前3段超网）。"""
    idx = {}
    for e in entries:
        net = e["net"]
        segs = V4_SEG if net.version == 4 else V6_SEG
        for plen in segs:
            if plen > net.prefixlen:
                # 条目网段比目标粒度还小(更精确), 无法反推同段超网, 跳过
                continue
            pref = net.supernet(new_prefix=plen)
            idx.setdefault(pref, []).append(e["raw"])
    return idx


def seg_label(version, plen):
    if version == 4:
        return "前2段(/16)" if plen == 16 else "前3段(/24)"
    return "前2段(/32)" if plen == 32 else "前3段(/48)"


def query_one(ip_str, black, white, black_fz, white_fz):
    try:
        ip = ipaddress.ip_address(clean_token(ip_str))
    except ValueError:
        return {"input": ip_str, "error": "无法解析的 IP"}

    version = ip.version
    segs = V4_SEG if version == 4 else V6_SEG

    def exact(entries):
        hits = []
        for e in entries:
            if e["version"] != version:
                continue
            if ip in e["net"]:
                hits.append(e["raw"])
        return hits

    def fuzzy(fz_index):
        # plen -> [raw, ...]
        res = {}
        for plen in segs:
            pref = ipaddress.ip_network("%s/%d" % (ip, plen), strict=False)
            raws = fz_index.get(pref)
            if raws:
                res[plen] = raws
        return res

    return {
        "input": ip_str,
        "ip": str(ip),
        "version": version,
        "black_exact": exact(black),
        "white_exact": exact(white),
        "black_fuzzy": fuzzy(black_fz),
        "white_fuzzy": fuzzy(white_fz),
    }


def fmt_hits(hits, limit=5):
    if not hits:
        return "未命中"
    uniq = []
    for h in hits:
        if h not in uniq:
            uniq.append(h)
    if len(uniq) <= limit:
        return ", ".join(uniq)
    return ", ".join(uniq[:limit]) + " 等 %d 条" % len(uniq)


def format_report(results, black_n, white_n):
    lines = []
    lines.append("=" * 56)
    lines.append("IP 查询结果")
    lines.append("=" * 56)
    lines.append("黑名单: %s (%d 条)" % (os.path.basename(BLACK_FILE), black_n))
    lines.append("白名单: %s (%d 条)" % (os.path.basename(WHITE_FILE), white_n))
    lines.append("查询 IP 总数: %d" % len(results))
    lines.append("")

    s_b_exact = s_b_fuzzy = s_w_exact = s_w_fuzzy = s_conflict = 0
    for r in results:
        if "error" in r:
            lines.append("[%s]  ->  %s" % (r["input"], r["error"]))
            lines.append("")
            continue
        be, we = r["black_exact"], r["white_exact"]
        bf, wf = r["black_fuzzy"], r["white_fuzzy"]
        if be:
            s_b_exact += 1
        if we:
            s_w_exact += 1
        if bf:
            s_b_fuzzy += 1
        if wf:
            s_w_fuzzy += 1
        if be and we:
            s_conflict += 1

        lines.append("[%s]  (%s)" % (r["ip"], "IPv%d" % r["version"]))

        # 黑名单
        if be:
            lines.append("  黑名单:  精确命中 -> %s" % fmt_hits(be))
        elif bf:
            parts = []
            for plen, raws in sorted(bf.items()):
                parts.append("    %s -> %s" % (seg_label(r["version"], plen), fmt_hits(raws)))
            lines.append("  黑名单:  模糊命中")
            lines.extend("            " + p if False else "            " + p for p in parts)
        else:
            lines.append("  黑名单:  未命中")

        # 白名单
        if we:
            lines.append("  白名单:  精确命中 -> %s" % fmt_hits(we))
            lines.append("            => 建议放行")
        elif wf:
            parts = []
            for plen, raws in sorted(wf.items()):
                parts.append("    %s -> %s" % (seg_label(r["version"], plen), fmt_hits(raws)))
            lines.append("  白名单:  模糊命中")
            for p in parts:
                lines.append("            " + p)
            lines.append("            => 同网段, 需人工确认")
        else:
            lines.append("  白名单:  未命中")
        lines.append("")

    lines.append("=" * 56)
    lines.append("汇总")
    lines.append("=" * 56)
    lines.append("黑名单 精确命中: %d" % s_b_exact)
    lines.append("黑名单 模糊命中: %d" % s_b_fuzzy)
    lines.append("白名单 精确命中: %d" % s_w_exact)
    lines.append("白名单 模糊命中: %d" % s_w_fuzzy)
    if s_conflict:
        lines.append("⚠ 黑白同时精确命中(冲突): %d  (白名单优先, 但请复核)" % s_conflict)
    lines.append("=" * 56)
    return "\n".join(lines)


def read_lines(path):
    out = []
    with open(path, "r", encoding="utf-8-sig") as f:
        for line in f:
            t = clean_token(line)
            if t:
                out.append(t)
    return out


def next_seq(path):
    maxn = 0
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            for row in csv.reader(f):
                if row and row[0].isdigit():
                    maxn = max(maxn, int(row[0]))
    return maxn + 1


def unique_preserve(items):
    """去重且保持首次出现顺序。"""
    seen = set()
    out = []
    for x in items:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def exact_in_entries(ip_or_cidr, entries):
    """判断是否已在名单中精确存在。
    单 IP: 落在任一名单网段/单 IP 内即算精确命中。
    CIDR: 名单中存在相同 network 才算精确已存在。
    """
    token = clean_token(ip_or_cidr)
    if not token:
        return False
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return False
    if net.num_addresses == 1:
        ip = ipaddress.ip_address(net.network_address)
        for e in entries:
            if e["version"] == ip.version and ip in e["net"]:
                return True
        return False
    for e in entries:
        if e["version"] == net.version and e["net"] == net:
            return True
    return False


def add_entries(kind, tokens, dedupe=False, existing_entries=None):
    """向黑/白名单追加。

    dedupe=True 时跳过已在 existing_entries 中精确命中的条目。
    返回实际写入条数。
    黑名单默认表头为两列「序号,封禁IP」；若已有文件表头含封禁日期/时间则沿用四列写入以兼容旧表。
    """
    if kind == "black":
        path = BLACK_FILE
        header = ["序号", "封禁IP"]
        use_datetime = False
        if os.path.exists(path) and os.path.getsize(path) > 0:
            with open(path, "r", encoding="utf-8-sig", newline="") as f:
                rows = list(csv.reader(f))
            if rows:
                hdr = [clean_token(h) for h in rows[0]]
                if any("封禁日期" in h for h in hdr) or len(hdr) >= 4:
                    header = ["序号", "封禁IP", "封禁日期", "封禁时间"]
                    use_datetime = True
    else:
        path = WHITE_FILE
        header = ["序号", "白名单"]
        use_datetime = False

    valid = []
    for tok in tokens:
        tok = clean_token(tok)
        if not tok:
            continue
        try:
            ipaddress.ip_network(tok, strict=False)
        except ValueError:
            print("跳过无法解析的条目: %s" % tok)
            continue
        valid.append(tok)
    valid = unique_preserve(valid)
    if not valid:
        print("没有可添加的合法条目。")
        return 0

    skipped = 0
    if dedupe:
        if existing_entries is None:
            existing_entries = []
        kept = []
        for tok in valid:
            if exact_in_entries(tok, existing_entries):
                skipped += 1
            else:
                kept.append(tok)
        valid = kept
        if not valid:
            print("全部 %d 条均已在名单中精确命中，未写入。" % skipped)
            return 0

    file_exists = os.path.exists(path) and os.path.getsize(path) > 0
    seq = next_seq(path)
    today = now = None
    if use_datetime:
        from datetime import datetime
        today = datetime.now().strftime("%Y/%m/%d")
        now = datetime.now().strftime("%H:%M:%S")

    with open(path, "a", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f, lineterminator="\n")
        if not file_exists:
            w.writerow(header)
        for tok in valid:
            if use_datetime:
                w.writerow([seq, tok, today, now])
            else:
                w.writerow([seq, tok])
            seq += 1

    msg = "已向 %s 追加 %d 条。" % (os.path.basename(path), len(valid))
    if dedupe and skipped:
        msg += "（去重跳过 %d 条）" % skipped
    print(msg)
    return len(valid)

def load_all():
    """一次性加载黑/白名单及模糊索引。"""
    b_entries, b_err, b_warn = load_list(BLACK_FILE, "封禁IP")
    w_entries, w_err, w_warn = load_list(WHITE_FILE, "白名单")
    b_fz = build_fuzzy_index(b_entries)
    w_fz = build_fuzzy_index(w_entries)
    return b_entries, w_entries, b_fz, w_fz, b_err, w_err, b_warn, w_warn


def format_interactive(results):
    """对话模式使用的紧凑结果格式（不含大横幅，便于连续查看）。"""
    lines = []
    sb = sw = sbf = swf = sc = 0
    for r in results:
        if "error" in r:
            lines.append("[%s]  ->  %s" % (r["input"], r["error"]))
            continue
        be, we = r["black_exact"], r["white_exact"]
        bf, wf = r["black_fuzzy"], r["white_fuzzy"]
        if be:
            sb += 1
        if we:
            sw += 1
        if bf:
            sbf += 1
        if wf:
            swf += 1
        if be and we:
            sc += 1
        lines.append("-" * 56)
        lines.append("[%s]  (%s)" % (r["ip"], "IPv%d" % r["version"]))
        if be:
            lines.append("  黑名单: 精确命中 -> %s" % fmt_hits(be))
        elif bf:
            parts = []
            for plen, raws in sorted(bf.items()):
                parts.append("    %s -> %s" % (seg_label(r["version"], plen), fmt_hits(raws)))
            lines.append("  黑名单: 模糊命中")
            lines.extend("            " + p for p in parts)
        else:
            lines.append("  黑名单: 未命中")
        if we:
            lines.append("  白名单: 精确命中 -> %s" % fmt_hits(we))
            lines.append("            => 建议放行")
        elif wf:
            parts = []
            for plen, raws in sorted(wf.items()):
                parts.append("    %s -> %s" % (seg_label(r["version"], plen), fmt_hits(raws)))
            lines.append("  白名单: 模糊命中")
            for p in parts:
                lines.append("            " + p)
            lines.append("            => 同网段, 需人工确认")
        else:
            lines.append("  白名单: 未命中")
    lines.append("=" * 56)
    lines.append("共 %d 个 | 黑精确 %d | 黑模糊 %d | 白精确 %d | 白模糊 %d%s"
                 % (len(results), sb, sbf, sw, swf, (" | ⚠冲突 %d" % sc) if sc else ""))
    return "\n".join(lines)


def interactive_help():
    print("命令一览:")
    print("  (直接输入 IP)  每行一个，空行 + 回车 执行批量查询")
    print("  go             立即执行已输入的 IP（与空行等效）")
    print("  add            交互式录入到黑白名单")
    print("  add <black|white> <IP/CIDR ...>   单行录入")
    print("  reload         重新读取 CSV（手动改完文件后用）")
    print("  clear          清屏")
    print("  help           显示本帮助")
    print("  exit / quit    退出")
    print("查完后可选:")
    print("  [a] 全量追加 — 本批全部写入黑名单（允许与现有重复）")
    print("  [b] 去重追加 — 跳过已在黑名单精确命中的，只写入其余")
    print("  [c] 不追加")


def start_interactive():
    b_entries, w_entries, b_fz, w_fz, b_err, w_err, b_warn, w_warn = load_all()

    def reload_lists():
        nonlocal b_entries, w_entries, b_fz, w_fz, b_err, w_err, b_warn, w_warn
        b_entries, w_entries, b_fz, w_fz, b_err, w_err, b_warn, w_warn = load_all()

    buffer = []

    def prompt_append_blacklist(results):
        """查完后三选一追加黑名单；仅对话模式调用。"""
        nonlocal b_entries, w_entries, b_fz, w_fz, b_err, w_err, b_warn, w_warn
        ok = [r for r in results if not r.get("error")]
        if not ok:
            return
        n = len(ok)
        n_hit = sum(1 for r in ok if r.get("black_exact"))
        n_new = n - n_hit
        print("本批 %d 个可解析 IP（黑名单精确命中 %d / 未精确命中 %d）。是否追加到黑名单？"
              % (n, n_hit, n_new))
        print("  [a] 全量追加 — 本批全部写入（允许与现有条目重复）")
        print("  [b] 去重追加 — 跳过已在黑名单精确命中的，只写入其余")
        print("  [c] 不追加")
        try:
            choice = clean_token(input("选择 [a/b/c]: ")).lower()
        except (EOFError, KeyboardInterrupt):
            print("  已取消追加。")
            return
        if choice in ("", "c", "n", "no", "q"):
            print("  未追加。")
            return
        tokens = [r["ip"] for r in ok]
        if choice in ("a", "1"):
            add_entries("black", tokens, dedupe=False)
            reload_lists()
            return
        if choice in ("b", "2"):
            add_entries("black", tokens, dedupe=True, existing_entries=b_entries)
            reload_lists()
            return
        print("  无效选择，未追加。")

    def execute():
        if buffer:
            results = [query_one(ip, b_entries, w_entries, b_fz, w_fz) for ip in buffer]
            print(format_interactive(results))
            print()
            prompt_append_blacklist(results)
            buffer.clear()
        else:
            print("（没有待查询的 IP，先输入几个吧）")

    print("=" * 56)
    print("IP 黑白名单查询 · 对话模式")
    print("=" * 56)
    print("黑名单: %s (%d 条)    白名单: %s (%d 条)"
          % (os.path.basename(BLACK_FILE), len(b_entries),
             os.path.basename(WHITE_FILE), len(w_entries)))
    for w in b_warn + w_warn:
        print("⚠ [警告] %s" % w)
    for e in b_err + w_err:
        print("✗ [错误] %s" % e)
    print("输入 IP，每行一个；空行 + 回车 执行查询（直接粘贴多行也行）")
    print("输入 help 查看命令，exit 退出")
    print("=" * 56)
    print()

    # 关键点: 用 select 检测 stdin 是否还有「已缓冲的待读内容」。
    # 若有(说明刚才是整段粘贴)，则不打出 '> ' 提示符——避免终端回显与
    # 逐行提示符相互错位；若没有(手动逐行输入)，才在每个换行后打 '> '。
    def prompt_next():
        try:
            r, _, _ = select.select([sys.stdin], [], [], 0)
            pasted = bool(r)
        except (OSError, ValueError):
            pasted = False
        if not pasted:
            sys.stdout.write("> ")
            sys.stdout.flush()

    print("> ", end="", flush=True)
    while True:
        try:
            line = sys.stdin.readline()
        except KeyboardInterrupt:
            print("  (已取消当前输入，输入 exit 退出)")
            buffer.clear()
            print("> ", end="", flush=True)
            continue
        if line == "":  # Ctrl-D (EOF)
            print()
            break

        raw = clean_token(line)
        low = raw.lower()

        # ---- 命令 ----
        if low in ("exit", "quit", "q"):
            print("bye.")
            break
        if low in ("help", "h", "?"):
            interactive_help()
            prompt_next()
            continue
        if low in ("clear", "cls"):
            os.system("clear" if os.name == "posix" else "cls")
            prompt_next()
            continue
        if low == "go":
            execute()
            prompt_next()
            continue
        if low == "reload":
            reload_lists()
            print("已重新加载: 黑 %d 条, 白 %d 条" % (len(b_entries), len(w_entries)))
            for w in b_warn + w_warn:
                print("⚠ [警告] %s" % w)
            prompt_next()
            continue
        if low == "add":
            kind = input("  录入类型 (black/white): ").strip().lower()
            if kind not in ("black", "white"):
                print("  无效类型，已取消。")
                prompt_next()
                continue
            print("  输入 IP/CIDR，每行一个，空行结束:")
            toks = []
            while True:
                try:
                    l = input("    + ")
                except (EOFError, KeyboardInterrupt):
                    break
                t = clean_token(l)
                if t == "":
                    break
                toks.append(t)
            add_entries(kind, toks)
            reload_lists()
            prompt_next()
            continue
        if low.startswith("add "):
            parts = raw.split()
            kind = parts[1].lower() if len(parts) > 1 else ""
            toks = parts[2:] if len(parts) > 2 else []
            if kind not in ("black", "white"):
                print("用法: add <black|white> <IP/CIDR ...>")
                prompt_next()
                continue
            add_entries(kind, toks)
            reload_lists()
            prompt_next()
            continue

        # ---- 空行: 执行批量查询 ----
        if raw == "":
            execute()
            prompt_next()
            continue

        # ---- 普通 IP 行 ----
        buffer.append(raw)
        prompt_next()


def main():
    raw_argv = sys.argv[1:]

    # 无参数且为交互终端 -> 进入对话模式
    if not raw_argv and sys.stdin.isatty():
        start_interactive()
        return
    # 无参数但非交互(管道/重定向) -> 读 stdin 查一次
    if not raw_argv and not sys.stdin.isatty():
        raw_argv = ["query"]

    argv = raw_argv
    if argv and argv[0] in ("query", "add"):
        pass
    else:
        argv = ["query"] + argv

    parser = argparse.ArgumentParser(description="IP 黑白名单查询工具")
    sub = parser.add_subparsers(dest="cmd")

    pq = sub.add_parser("query", help="查询 IP 是否在黑白名单内")
    pq.add_argument("ips", nargs="*", help="要查询的 IP（空格分隔，可多个）")
    pq.add_argument("-f", "--file", help="从文件读取 IP（每行一个）")
    pq.add_argument("-o", "--output", help="将查询结果写入文件")

    pa = sub.add_parser("add", help="向黑白名单追加录入（可选）")
    pa.add_argument("kind", choices=["black", "white"], help="black=黑名单, white=白名单")
    pa.add_argument("tokens", nargs="*", help="IP 或 CIDR")
    pa.add_argument("-f", "--file", help="从文件批量读取（每行一个）")

    args = parser.parse_args(argv)

    if args.cmd == "add":
        tokens = list(args.tokens)
        if args.file:
            tokens += read_lines(args.file)
        add_entries(args.kind, tokens)
        return

    # ---- query ----
    ips = list(args.ips)
    if getattr(args, "file", None):
        ips += read_lines(args.file)
    if not ips and not sys.stdin.isatty():
        ips += [l for l in sys.stdin.read().splitlines()]

    if not ips:
        parser.print_help()
        return

    b_entries, b_err, b_warn = load_list(BLACK_FILE, "封禁IP")
    w_entries, w_err, w_warn = load_list(WHITE_FILE, "白名单")
    b_fz = build_fuzzy_index(b_entries)
    w_fz = build_fuzzy_index(w_entries)

    for w in b_warn + w_warn:
        print("⚠ [警告] %s" % w)
    for e in b_err + w_err:
        print("✗ [错误] %s" % e)

    results = [query_one(ip, b_entries, w_entries, b_fz, w_fz) for ip in ips]
    report = format_report(results, len(b_entries), len(w_entries))
    print(report)

    if getattr(args, "output", None):
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report + "\n")
        print("结果已写入: %s" % args.output)


if __name__ == "__main__":
    main()
