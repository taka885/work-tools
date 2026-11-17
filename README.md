# redhat-cve-tools

Red Hat の公開されている脆弱性情報（CVE）を集めて、まとめるためのスクリプト。

## rhel/rhel810_monthly.py
RHEL 8.10 の月次まとめ。前の月に公開された Critical/Important の CVE を CSV にする。

```
python3 rhel/rhel810_monthly.py            # 先月分（毎月1〜3日に実行）
python3 rhel/rhel810_monthly.py 2026-11    # 月を指定
```

- 条件は Red Hat の CVE 検索画面と同じ（products=Red Hat Enterprise Linux 8, Critical/Important, Red Hat の CVE だけ, 公開日がその月。月の区切りは UTC）。
- その月に公開された CVE なので、「Red Hat Enterprise Linux 8」の状態がそのまま 8.10 の状態になる。
- 8.10の状態: 修正済み / 一部修正済み / 未修正 / 影響なし（RHEL 8 はすべて Not affected）
- 状態は実行した時点のもの。
- Python 3 だけで動く（追加のライブラリ不要）。
