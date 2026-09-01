#!/usr/bin/env python3
"""授權合規：讀 license.manifest → 比對政策 → 產出 notice 與判定。

依 CICD_CT.pdf 第 17 頁 License compliance。**不從 build 端擋任何授權**
（沒有設 INCOMPATIBLE_LICENSE），閘門抓的是「出現沒人看過的授權」。

exit 0 = PASS、1 = BLOCK（有未分類的授權）。設計依據見 docs/GATES.md。
"""

import argparse
import collections
import datetime
import glob
import json
import os
import re
import sys

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY = os.path.join(REPO, "build-container", "tmp", "deploy")
MANIFEST_GLOB = os.path.join(DEPLOY, "licenses", "*", "*", "license.manifest")
DEFAULT_POLICY = os.path.join(REPO, "policy", "license-policy.yml")
SPLIT_RE = re.compile(r"\s+(?:AND|OR)\s+")


def newest_manifest(pattern):
    hits = [p for p in glob.glob(pattern) if not os.path.islink(p)]
    if not hits:
        sys.exit(f"找不到 license.manifest：{pattern}")
    return max(hits, key=os.path.getmtime)


def identifiers(expr):
    """把授權運算式拆成個別識別碼。

    "A WITH B" 保持完整 —— 例外條款會改變義務，拆開就失去意義。
    比對整串運算式行不通：同樣一組授權換個組合就是新字串，會製造大量假警報。
    """
    expr = expr.replace("(", " ").replace(")", " ")
    return [t.strip() for t in SPLIT_RE.split(expr) if t.strip()]


def read_manifest(path):
    pkgs = []
    for block in open(path, encoding="utf-8").read().split("\n\n"):
        fields = dict(re.findall(
            r"^(PACKAGE NAME|PACKAGE VERSION|RECIPE NAME|LICENSE):\s*(.*)$",
            block, re.M))
        if fields.get("PACKAGE NAME"):
            pkgs.append({
                "package": fields["PACKAGE NAME"].strip(),
                "version": fields.get("PACKAGE VERSION", "").strip(),
                "recipe": fields.get("RECIPE NAME", "").strip(),
                "license": fields.get("LICENSE", "").strip(),
            })
    return pkgs


def license_texts(recipes):
    """每個出貨 recipe 的授權全文檔案。

    Yocto 放在 deploy/licenses/<arch>/<recipe>/：generic_<授權> 是標準全文，
    LICENSE* 是套件自帶的那份。兩種都要收 —— 標準全文滿足「附上授權條款」，
    套件自帶的常含著作權聲明，那是另一項義務。
    """
    found = {}
    for recipe in sorted(recipes):
        for d in glob.glob(os.path.join(DEPLOY, "licenses", "*", recipe)):
            files = [f for f in sorted(os.listdir(d)) if f != "recipeinfo"]
            if files:
                found[recipe] = (d, files)
                break
    return found


def write_notice(path, pkgs, texts, generated):
    """可交付的第三方授權聲明。

    GPL/LGPL 要求隨產品提供授權全文與著作權聲明，這是法律義務，與閘門擋不擋無關。
    標準全文去重（同一份 GPL-2.0 不必抄 40 遍），套件自帶的逐一收錄。
    """
    by_recipe = {}
    for p in pkgs:
        by_recipe.setdefault(p["recipe"] or p["package"], p["license"])

    generic, own = {}, []
    for recipe, (d, files) in texts.items():
        for f in files:
            full = os.path.join(d, f)
            if f.startswith("generic_"):
                generic.setdefault(f[len("generic_"):],
                                   open(full, encoding="utf-8", errors="replace").read())
            else:
                own.append((recipe, f, full))

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("THIRD-PARTY SOFTWARE NOTICES\n")
        fh.write(f"core-image-base / raspberrypi4-64 / panda\n產生時間：{generated}\n\n")
        fh.write(f"本產品包含以下 {len(by_recipe)} 個開源元件。\n")
        fh.write("依 GPL / LGPL 等授權要求，授權全文與著作權聲明附於後。\n")
        fh.write("\n" + "=" * 78 + "\n元件清單\n" + "=" * 78 + "\n\n")
        for recipe, lic in sorted(by_recipe.items()):
            fh.write(f"{recipe}\n    {lic}\n")
        fh.write("\n" + "=" * 78 + "\n授權全文\n" + "=" * 78 + "\n")
        for name, text in sorted(generic.items()):
            fh.write(f"\n\n----- {name} -----\n\n{text}")
        fh.write("\n\n" + "=" * 78 + "\n各元件自帶的授權與著作權聲明\n" + "=" * 78 + "\n")
        for recipe, fname, full in sorted(own):
            fh.write(f"\n\n----- {recipe} / {fname} -----\n\n")
            fh.write(open(full, encoding="utf-8", errors="replace").read())
    return len(by_recipe), len(generic), len(own)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default=DEFAULT_POLICY)
    ap.add_argument("--manifest", help="預設取最新的")
    ap.add_argument("--out", default=os.path.join(DEPLOY, "release"))
    ap.add_argument("--json", help="判定結果寫成 JSON")
    args = ap.parse_args()

    with open(args.policy, encoding="utf-8") as fh:
        policy = yaml.safe_load(fh)
    manifest = args.manifest or newest_manifest(MANIFEST_GLOB)
    os.makedirs(args.out, exist_ok=True)

    pkgs = read_manifest(manifest)
    accepted = set(policy.get("accepted", []))
    counts = collections.Counter()
    for p in pkgs:
        for i in identifiers(p["license"]):
            counts[i] += 1

    unknown = sorted(set(counts) - accepted)
    restricted = []
    for group in policy.get("restricted", []):
        hits = {l: counts[l] for l in group.get("licenses", []) if counts.get(l)}
        if hits:
            restricted.append({
                "id": group["id"],
                "hits": hits,
                "why": " ".join((group.get("why") or "").split()),
                "note": " ".join((group.get("note") or "").split()),
                "packages": sorted({p["recipe"] or p["package"] for p in pkgs
                                    if set(identifiers(p["license"])) & set(hits)}),
            })

    generated = datetime.datetime.now().isoformat(timespec="seconds")
    texts = license_texts({p["recipe"] or p["package"] for p in pkgs})
    notice = os.path.join(args.out, "THIRD-PARTY-NOTICES.txt")
    n_comp, n_generic, n_own = write_notice(notice, pkgs, texts, generated)

    verdict = "BLOCK" if unknown else "PASS"
    reason = (f"{len(unknown)} 個授權沒有分類過" if unknown
              else f"{len(counts)} 個授權識別碼全部已分類")

    print(f"manifest：{os.path.relpath(manifest, REPO)}")
    print(f"規則：{os.path.relpath(args.policy, REPO)}    日期：{generated[:10]}\n")
    print(f"  套件 {len(pkgs)}    元件（recipe）{n_comp}    授權識別碼 {len(counts)}")
    print(f"  notice：{os.path.relpath(notice, REPO)}"
          f"（標準全文 {n_generic} 份、元件自帶 {n_own} 份）")

    if unknown:
        print("\n❌ 沒有分類過的授權（每一個都要有人看過並歸類）：")
        for u in unknown:
            print(f"    {u}    {counts[u]} 個套件")

    for r in restricted:
        total = sum(r["hits"].values())
        print(f"\n⚠️  {r['id']}：{total} 個套件 —— {'、'.join(r['packages'][:6])}")
        print(f"    {r['why'][:150]}")

    print(f"\n{'=' * 62}\n判定：{verdict} —— {reason}\n{'=' * 62}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({
                "verdict": verdict, "reason": reason, "generated": generated,
                "manifest": os.path.basename(manifest),
                "policy_version": policy.get("version"),
                "packages": len(pkgs), "components": n_comp,
                "identifiers": dict(sorted(counts.items())),
                "unknown": unknown, "restricted": restricted,
                "notice": os.path.relpath(notice, REPO),
            }, fh, ensure_ascii=False, indent=2)
        print(f"判定結果已寫入 {os.path.relpath(args.json, REPO)}")

    return 1 if unknown else 0


if __name__ == "__main__":
    sys.exit(main())
