#!/usr/bin/env python3
"""RHEL 8.10 の月次まとめ: その月に公開された Critical/Important の CVE を CSV にする。

条件は Red Hat の CVE 検索画面と同じ:
  products=Red Hat Enterprise Linux 8, cve_threatSeverity=Critical,Important, rhCVE=true,
  公開日がその月の1日〜末日（画面と同じく UTC で区切る）
その月に公開された CVE なら、RHEL 8 の修正は必ず 8.10 GA（2024-05-22）より後に出る。
なので「Red Hat Enterprise Linux 8」の状態が、そのまま 8.10 の状態になる。

使い方: python3 rhel810_monthly.py [YYYY-MM] [出力.csv]
  月を省くと先月（日本時間で数える）。出力を省くと rhel810_YYYY-MM.csv。
"""
import calendar, collections, csv, datetime, json, sys, urllib.parse, urllib.request

API = "https://access.redhat.com/hydra/rest/search/kcs"  # 検索画面が使っているのと同じ検索
PRODUCT = "Red Hat Enterprise Linux 8"
UNFIXED = {"Affected", "Fix deferred", "Will not fix", "Under investigation", "Out of support scope"}
SEV_ORDER = {"Critical": 0, "Important": 1}
ROWS = 500


def prev_month():
    today = datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=9))).date()
    last = today.replace(day=1) - datetime.timedelta(days=1)
    return f"{last.year:04d}-{last.month:02d}"


def search(start, end):
    fq_main = (f"cve_publicDate:([{start}T00:00:00.000Z TO {end}T23:59:59.000Z])"
               ' AND documentKind:("Cve") AND language:("en")'
               " AND cve_threatSeverity:(Critical OR Important)"
               " AND unaffected_cve_record:false")
    fq_product = "platform_state_string:(" + PRODUCT.replace(" ", "\\ ") + "|*)"
    fields = "allTitle,cve_threatSeverity,cvss3_base_score,cve_publicDate,cve_details,view_uri,cve_state_package"
    docs, total = [], None
    while total is None or len(docs) < total:
        query = urllib.parse.urlencode([
            ("q", "*"), ("fq", fq_main), ("fq", fq_product), ("fl", fields),
            ("rows", ROWS), ("start", len(docs)), ("sort", "cve_publicDate asc,allTitle asc")])
        req = urllib.request.Request(f"{API}?{query}", headers={"User-Agent": "curl/8.0"})  # Python 既定の UA は 403 になる
        with urllib.request.urlopen(req, timeout=120) as r:
            res = json.load(r)["response"]
        total = res["numFound"]
        if not res["docs"]:
            break
        docs += res["docs"]
    return docs, total


def summarize(doc):
    entries = [e for e in json.loads(doc.get("cve_state_package") or "[]") if e.get("product") == PRODUCT]
    states = {e.get("state") for e in entries}
    unfixed = states & UNFIXED
    if unfixed and "Fixed" in states:
        overall = "一部修正済み"
    elif unfixed:
        overall = "未修正"
    elif "Fixed" in states:
        overall = "修正済み"
    elif states == {"Not affected"}:
        overall = "影響なし"
    else:
        overall = "/".join(sorted(s for s in states if s))
    by_pkg = "; ".join(sorted({f'{e.get("package")}: {e.get("state")}' for e in entries}))
    advs = sorted({(e["advisory"]["name"], e["advisory"]["release_date"][:10])
                   for e in entries if e.get("advisory")}, key=lambda a: (a[1], a[0]))
    return [
        doc["allTitle"],
        doc.get("cve_threatSeverity", ""),
        doc.get("cvss3_base_score", ""),
        doc.get("cve_publicDate", "")[:10],
        overall,
        by_pkg,
        " ".join(a[0] for a in advs),
        " ".join(a[1] for a in advs),
        " ".join((doc.get("cve_details") or "").split()),
        doc.get("view_uri", ""),
    ]


def main():
    ym = sys.argv[1] if len(sys.argv) > 1 else prev_month()
    out = sys.argv[2] if len(sys.argv) > 2 else f"rhel810_{ym}.csv"
    y, m = map(int, ym.split("-"))
    start, end = f"{y:04d}-{m:02d}-01", f"{y:04d}-{m:02d}-{calendar.monthrange(y, m)[1]:02d}"

    docs, total = search(start, end)
    if len(docs) != total:
        sys.exit(f"取得件数が合いません: {len(docs)} / {total}")
    rows = sorted((summarize(d) for d in docs), key=lambda r: (SEV_ORDER.get(r[1], 9), r[3], r[0]))

    with open(out, "w", newline="", encoding="utf-8-sig") as fp:  # Excel でそのまま開ける
        w = csv.writer(fp)
        w.writerow(["CVE", "重大度", "CVSS v3", "公開日(UTC)", "8.10の状態", "パッケージごとの状態",
                    "修正RHSA", "RHSA公開日", "概要", "URL"])
        w.writerows(rows)

    print(f"{ym}（{start}〜{end} UTC）: {len(rows)} 件 → {out}")
    count = collections.Counter((r[1], r[4]) for r in rows)
    for sev in sorted({r[1] for r in rows}, key=lambda s: SEV_ORDER.get(s, 9)):
        detail = ", ".join(f"{st} {n}" for (s, st), n in sorted(count.items()) if s == sev)
        print(f"  {sev}: {sum(n for (s, _), n in count.items() if s == sev)} 件（{detail}）")


if __name__ == "__main__":
    main()
