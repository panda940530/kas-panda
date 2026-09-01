#!/usr/bin/env python3
"""Release gate：收集證據 → 產出 release manifest → 判定要不要 promote。

依 CICD_CT.pdf 第 16、17 頁。頻道語意：
  exit 0 = RC       必要證據齊全且缺口全關
  exit 1 = BLOCK    必要證據缺漏，或 CVE / CT 沒過
  exit 2 = nightly  必要證據齊全，但仍有未關閉的缺口

設計依據見 docs/NOTES.md §9。
"""

import argparse
import datetime
import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import sys

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEPLOY = os.path.join(REPO, "build-container", "tmp", "deploy")
IMAGES = os.path.join(DEPLOY, "images", "*")
DEFAULT_POLICY = os.path.join(REPO, "policy", "release-policy.yml")
DEFAULT_OUT = os.path.join(DEPLOY, "release")
CVE_GATE = os.path.join(REPO, "policy", "cve-gate.py")
LICENSE_GATE = os.path.join(REPO, "policy", "license-gate.py")
HARDENING_BASELINE = os.path.join(
    REPO, "meta-panda", "lib", "oeqa", "runtime", "cases",
    "hardening-baseline.json")
STAMP_RE = re.compile(r"(\d{14})")
COOKER_LOGS = os.path.join(REPO, "build-container", "tmp", "log", "cooker", "*",
                           "*.log")
# bitbake 的 Build Configuration 用 layer 名，panda.yml 用 repo 名
LAYER_TO_REPO = {
    "meta": "openembedded-core",
    "meta-poky": "meta-yocto",
    "meta-yocto-bsp": "meta-yocto",
    "meta-raspberrypi": "meta-raspberrypi",
    "meta-panda": "meta-panda",
}
BUILDCFG_RE = re.compile(r'^(\S+)\s+= "([^":]+):([0-9a-f]{40})"\s*$', re.M)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def newest(pattern):
    """取最新的真實檔案。symlink 一律排除 —— 它們是同一份東西的第二個名字。"""
    hits = [p for p in glob.glob(pattern) if not os.path.islink(p)]
    return max(hits, key=os.path.getmtime) if hits else None


def newest_excluding(pattern, exclude):
    """純 SBOM 與 CVE 註記版的副檔名相同，只差中間那段，glob 無法只靠萬用字元分開。"""
    hits = [p for p in glob.glob(pattern)
            if not os.path.islink(p) and exclude not in os.path.basename(p)]
    return max(hits, key=os.path.getmtime) if hits else None


def evidence(path):
    """一份證據的指紋。stamp 是檔名裡的 IMAGE_NAME 時間戳，用來看各份證據同不同批。"""
    if not path or not os.path.exists(path):
        return None
    # 用完整路徑找戳記：license.manifest 的戳記在上層目錄名，不在檔名裡
    m = STAMP_RE.search(path)
    return {
        "path": os.path.relpath(path, REPO),
        "sha256": sha256(path),
        "bytes": os.path.getsize(path),
        "mtime": datetime.datetime.fromtimestamp(
            os.path.getmtime(path)).isoformat(timespec="seconds"),
        "image_stamp": m.group(1) if m else None,
    }


def run_cve_gate(out_dir):
    """直接跑 cve-gate.py，不讀舊的 verdict —— 兩個 gate 必須看同一份現況。"""
    verdict_path = os.path.join(out_dir, "cve-verdict.json")
    proc = subprocess.run(
        [sys.executable, CVE_GATE, "--json", verdict_path],
        capture_output=True, text=True)
    if not os.path.exists(verdict_path):
        return None, None, proc.stdout + proc.stderr
    with open(verdict_path, encoding="utf-8") as fh:
        return json.load(fh), verdict_path, proc.stdout


def hardening_summary(path):
    """讀執行期基準線，數出「出貨變體必須改掉」的項目。

    CT 斷言的是「現況 == 基準線」（所以今天會過）；這裡讀的是基準線上的註記，
    回答另一個問題：這顆夠不夠格出貨。兩件事分開，CT 才不會變成永遠紅的燈。
    """
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        base = json.load(fh)
    blocking = []
    for section in ("tcp", "udp", "login_accounts", "empty_password"):
        for key, meta in (base.get(section) or {}).items():
            if isinstance(meta, dict) and meta.get("ship_blocking"):
                blocking.append({"section": section, "item": key,
                                 "why": " ".join((meta.get("why") or "").split())})
    return {"captured": base.get("captured"),
            "ship_blocking": blocking,
            "services_to_remove": {k: v for k, v in
                                   (base.get("services_to_remove") or {}).items()
                                   if not k.startswith("_")}}


def run_license_gate(out_dir):
    """跑授權合規判定，拿回 verdict 與 notice 的路徑。

    與 CVE 同樣的形狀：現場跑，不讀舊的判定 —— 兩個 gate 必須看同一份現況。
    """
    verdict_path = os.path.join(out_dir, "license-verdict.json")
    subprocess.run(
        [sys.executable, LICENSE_GATE, "--out", out_dir, "--json", verdict_path],
        capture_output=True, text=True)
    if not os.path.exists(verdict_path):
        return None, None
    with open(verdict_path, encoding="utf-8") as fh:
        return json.load(fh), verdict_path


def run_secret_scan(out_dir):
    """對兩個 repo 掃完整歷史找洩漏的憑證。

    現場掃而不是讀舊報告 —— 掃一次不到 0.1 秒，沒有「報告過期」這個問題。
    找不到 gitleaks 時回 None，呼叫端據此保留缺口，不要當成掃過了。

    ⚠️ gitleaks 的原始報告帶著那顆密鑰本身。直接收進 release bundle 等於把洩漏的
    東西再抄一份，所以原始報告寫到暫存檔，只有脫敏後的中繼資料留下來。
    """
    if shutil.which("gitleaks") is None:
        return None

    findings, scanned = [], []
    keep = ("RuleID", "Description", "File", "StartLine", "Commit", "Author", "Date")
    for name, path in (("kas-panda", REPO),
                       ("meta-panda", os.path.join(REPO, "meta-panda"))):
        if not os.path.isdir(os.path.join(path, ".git")):
            continue
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            raw = tmp.name
        try:
            subprocess.run(
                ["gitleaks", "detect", "--source", path, "--report-format", "json",
                 "--report-path", raw, "--no-banner"],
                capture_output=True, text=True)
            with open(raw, encoding="utf-8") as fh:
                data = json.load(fh) or []
        except (json.JSONDecodeError, OSError):
            data = []
        finally:
            os.unlink(raw)
        commits = subprocess.run(["git", "-C", path, "rev-list", "--count", "HEAD"],
                                 capture_output=True, text=True).stdout.strip()
        scanned.append({"repo": name, "commits": commits})
        for f in data:
            item = {k: f.get(k) for k in keep}
            item["repo"] = name
            findings.append(item)

    result = {"scanned": scanned, "findings": findings, "clean": not findings}
    path = os.path.join(out_dir, "secret-scan.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    result["report"] = path
    return result


def ct_summary(path):
    """testresults.json 裡有歷次執行，取時間戳最大的那一次。"""
    if not path or not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not data:
        return None
    run = max(data, key=lambda k: (STAMP_RE.search(k).group(1)
                                   if STAMP_RE.search(k) else ""))
    counts = {}
    for case in data[run].get("result", {}).values():
        counts[case.get("status")] = counts.get(case.get("status"), 0) + 1
    # configuration.LAYERS 記著那次測試所用的 layer commit —— 唯一能把
    # 測試結果綁回某一顆 image 的欄位（時間戳綁不住，STARTTIME 是測試時間不是建置時間）
    layers = {}
    for layer, spec in (data[run].get("configuration", {})
                        .get("LAYERS", {}) or {}).items():
        repo = LAYER_TO_REPO.get(layer)
        if repo and spec.get("commit"):
            layers[repo] = spec["commit"]
    return {"run": run, "counts": counts, "layers": layers,
            "passed": counts.get("PASSED", 0),
            "failed": counts.get("FAILED", 0) + counts.get("ERROR", 0)}


def provenance():
    """可重建這顆 image 需要的一切：每個 layer 的 URL 與 commit，加上我們自己的 commit。"""
    with open(os.path.join(REPO, "panda.yml"), encoding="utf-8") as fh:
        panda = yaml.safe_load(fh)
    lock_path = os.path.join(REPO, "panda.lock.yml")
    lock = {}
    if os.path.exists(lock_path):
        with open(lock_path, encoding="utf-8") as fh:
            lock = (yaml.safe_load(fh) or {}).get("overrides", {}).get("repos", {})

    layers = {}
    for name, spec in (panda.get("repos") or {}).items():
        spec = spec or {}
        layers[name] = {
            "url": spec.get("url"),
            "branch": spec.get("branch"),
            # panda.yml 手寫的 pin 優先；其餘由 kas lock 決定
            "commit": spec.get("commit") or lock.get(name, {}).get("commit"),
        }

    def head(path):
        try:
            return subprocess.run(["git", "-C", path, "rev-parse", "HEAD"],
                                  capture_output=True, text=True,
                                  check=True).stdout.strip()
        except Exception:
            return None

    return {
        "kas_panda_commit": head(REPO),
        "machine": panda.get("machine"),
        "distro": panda.get("distro"),
        "target": panda.get("target"),
        "layers": layers,
    }


def built_from(image_stamp):
    """建出這顆 image 的那次 bitbake 用了哪些 commit —— 由 bitbake 自己記錄。

    tmp/log/cooker/<machine>/<戳記>.log 開頭的 Build Configuration 區塊，
    是唯一能回答「證據到底是哪份原始碼建出來的」的權威來源。

    ⚠️ 不能用 console-latest.log。照 build → testimage → 判定的流程走，
    testimage 本身也是一次 bitbake 執行，會把 console-latest.log 指到自己身上。
    拿它當基準，pin 比的是「宣告 vs CT 當時」、CT drift 比的是
    「CT 當時 vs CT 當時」——後者恆等，等於沒檢查。

    改成挑「戳記不晚於 image 戳記」之中最新的那支：cooker log 的戳記是 bitbake
    起跑時間，必然早於它產出的 image 戳記，而後來的執行都會晚於它。
    """
    if not image_stamp:
        return None, None
    cands = []
    for path in glob.glob(COOKER_LOGS):
        if os.path.islink(path):          # console-latest.log
            continue
        m = STAMP_RE.search(os.path.basename(path))
        if m and m.group(1) <= image_stamp:
            cands.append((m.group(1), path))
    if not cands:
        return None, None
    log = max(cands)[1]
    with open(log, encoding="utf-8", errors="replace") as fh:
        head = fh.read(8192)
    used = {}
    for layer, _branch, commit in BUILDCFG_RE.findall(head):
        repo = LAYER_TO_REPO.get(layer)
        if repo:
            used[repo] = commit
    return used, log


def patched_on_top(repo, declared, actual):
    """actual 是不是「declared 加上疊在上面的 commit」。

    kas 的 patches: 會把 patch 做成一顆 commit 疊在 pin 上，layer HEAD 因此不等於
    宣告的 pin（例：meta-raspberrypi 的 "kas: fix-parselogs"）。這不是漂移 ——
    宣告的東西都在，只是多了我們自己加的，而 patch 檔本身也在版控裡。

    回傳多出來的 commit；不是祖先關係就回 None（那才是真的用了別的東西）。
    """
    path = os.path.join(REPO, repo)
    if not os.path.isdir(os.path.join(path, ".git")):
        return None
    ok = subprocess.run(
        ["git", "-C", path, "merge-base", "--is-ancestor", declared, actual],
        capture_output=True)
    if ok.returncode != 0:
        return None
    out = subprocess.run(
        ["git", "-C", path, "log", "--oneline", f"{declared}..{actual}"],
        capture_output=True, text=True)
    return [l for l in out.stdout.splitlines() if l.strip()]


def parse_gaps(raw, today):
    out = []
    for g in raw:
        expires = g.get("expires")
        if isinstance(expires, str):
            expires = datetime.date.fromisoformat(expires)
        if expires is None:
            sys.exit(f"gap {g.get('id')} 沒有 expires —— 不接受沒有期限的缺口")
        out.append({
            "id": g["id"], "what": g.get("what", ""),
            "why": " ".join((g.get("why") or "").split()),
            "owner": g.get("owner", "?"),
            "expires": expires.isoformat(),
            "expired": expires < today,
            "days_left": (expires - today).days,
        })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", default=DEFAULT_POLICY)
    ap.add_argument("--out", default=DEFAULT_OUT, help="release bundle 的存放目錄")
    args = ap.parse_args()

    with open(args.policy, encoding="utf-8") as fh:
        policy = yaml.safe_load(fh)
    today = datetime.date.today()
    os.makedirs(args.out, exist_ok=True)

    # ---- 收集 ----
    image = newest(os.path.join(IMAGES, "*.wic.bz2"))
    sbom = newest_excluding(os.path.join(IMAGES, "*.rootfs-*.spdx.json"),
                            "sbom-cve-check")
    cve_report = newest(os.path.join(IMAGES, "*.sbom-cve-check.yocto.json"))
    lic = newest(os.path.join(DEPLOY, "licenses", "*", "*", "license.manifest"))
    ct_path = os.path.join(REPO, "build-container", "tmp", "log", "oeqa",
                           "testresults.json")

    verdict, verdict_path, cve_out = run_cve_gate(args.out)
    ct = ct_summary(ct_path)
    secrets = run_secret_scan(args.out)
    lic_verdict, lic_verdict_path = run_license_gate(args.out)
    hardening = hardening_summary(HARDENING_BASELINE)

    items = {
        "image": evidence(image),
        "sbom": evidence(sbom),
        "cve_report": evidence(cve_report),
        "cve_verdict": evidence(verdict_path),
        "license_manifest": evidence(lic),
        "ct_report": evidence(ct_path),
        "secret_scan": evidence(secrets["report"]) if secrets else None,
        "license_verdict": evidence(lic_verdict_path),
        "license_notice": evidence(
            os.path.join(args.out, "THIRD-PARTY-NOTICES.txt")),
        "hardening_baseline": evidence(HARDENING_BASELINE),
    }

    # ---- 必要證據檢查 ----
    missing = []
    for req in policy.get("required") or []:
        rid = req["id"]
        if rid == "image_hash":
            ok = items["image"] is not None
        elif rid == "source_provenance":
            ok = True
        elif rid == "cve_verdict":
            ok = verdict is not None
        elif rid == "secret_scan":
            ok = secrets is not None
        elif rid == "license_verdict":
            ok = lic_verdict is not None
        else:
            ok = items.get(rid) is not None
        if not ok:
            missing.append(req)

    gaps = parse_gaps(policy.get("gaps") or [], today)
    if hardening and hardening["ship_blocking"]:
        n = len(hardening["ship_blocking"])
        gaps.append({
            "id": "hardening-ship-blocking",
            "what": f"{n} 項執行期設定在出貨變體必須改掉"
                    f"（{'、'.join(b['item'] for b in hardening['ship_blocking'])}）",
            "why": "基準線上標記 ship_blocking 的項目。CT 斷言的是現況與基準線一致，"
                   "夠不夠格出貨在這裡判。",
            "owner": "panda", "expires": "-", "expired": False, "days_left": 0,
        })
    if secrets is None:
        gaps.append({
            "id": "secret-scan-not-run", "what": "gitleaks 未安裝，這次沒有掃",
            "why": "找不到工具就保留缺口，不要當成掃過了",
            "owner": "panda", "expires": "-", "expired": False, "days_left": 0,
        })
    expired = [g for g in gaps if g["expired"]]

    # ---- 新鮮度：證據是不是對應現在這份原始碼 ----
    prov = provenance()
    # image 與 CVE 報告必須同一批：這兩者的對應關係是整份 manifest 的核心主張
    img_stamp = items["image"]["image_stamp"] if items["image"] else None
    cve_stamp = items["cve_report"]["image_stamp"] if items["cve_report"] else None
    batch_mismatch = bool(img_stamp and cve_stamp and img_stamp != cve_stamp)

    used, cooker_log = built_from(img_stamp)
    drift = []
    patched = []
    if used:
        for repo, declared in prov["layers"].items():
            actual = used.get(repo)
            if not (actual and declared.get("commit")) or actual == declared["commit"]:
                continue
            extra = patched_on_top(repo, declared["commit"], actual)
            if extra is None:
                drift.append({"repo": repo, "declared": declared["commit"],
                              "built_from": actual})
            else:
                patched.append({"repo": repo, "base": declared["commit"],
                                "head": actual, "commits": extra})
    # CT 結果是不是這顆 image 跑出來的。
    # ⚠️ kas 的 patches: 會把 patch 做成一顆 commit 疊在 pin 上，layer HEAD 因此
    #    不等於宣告的 pin —— 所以這裡比的是「CT 當時」對「image build 當時」，
    #    兩邊都是實際值，不是宣告值。
    ct_drift = []
    if ct and used:
        for repo, ct_commit in ct["layers"].items():
            built = used.get(repo)
            if built and built != ct_commit:
                ct_drift.append({"repo": repo, "ct": ct_commit, "image": built})

    cve_ok = verdict is not None and verdict.get("verdict") == "PASS"
    ct_ok = ct is not None and ct["failed"] == 0

    # 各份證據是不是同一批建置出來的
    stamps = sorted({v["image_stamp"] for v in items.values()
                     if v and v["image_stamp"]})

    # ---- 判定 ----
    reasons = []
    if missing:
        reasons.append("缺少必要證據：" + "、".join(m["id"] for m in missing))
    if not cve_ok:
        reasons.append(f"CVE 判定為 {verdict.get('verdict') if verdict else '無法取得'}")
    if not ct_ok:
        reasons.append("CT 有失敗案例" if ct else "沒有 CT 報告")
    if secrets and not secrets["clean"]:
        reasons.append(f"secret scan 找到 {len(secrets['findings'])} 筆疑似洩漏的憑證")
    if lic_verdict and lic_verdict.get("verdict") != "PASS":
        reasons.append(f"授權合規判定為 {lic_verdict['verdict']}：{lic_verdict['reason']}")
    if expired:
        reasons.append(f"{len(expired)} 項缺口已過期")
    if drift:
        reasons.append("宣告的 pin 與 build 實際使用的 commit 不一致："
                       + "、".join(d["repo"] for d in drift) + "（需重新 build）")
    if batch_mismatch:
        reasons.append(f"image（{img_stamp}）與 CVE 報告（{cve_stamp}）不是同一批建置")
    if used is None:
        reasons.append("找不到建出這顆 image 的 cooker log，無法確認證據對應哪份原始碼")
    if ct_drift:
        reasons.append("CT 結果不是這顆 image 跑出來的："
                       + "、".join(d["repo"] for d in ct_drift)
                       + "（用同一組 fragment 重跑 build + testimage）")

    if reasons:
        channel, code = "BLOCK", 1
    elif gaps:
        channel, code = "nightly", 2
        reasons.append(f"{len(gaps)} 項缺口未關閉，不得 promote 到 RC")
    else:
        channel, code = "RC", 0
        reasons.append("必要證據齊全，缺口全部關閉")

    manifest = {
        "generated": datetime.datetime.now().isoformat(timespec="seconds"),
        "channel": channel,
        "reasons": reasons,
        "policy_version": policy.get("version"),
        "image_stamps": stamps,
        "same_build": len(stamps) <= 1,
        "provenance": prov,
        "freshness": {
            "built_from": used,
            "cooker_log": os.path.relpath(cooker_log, REPO) if cooker_log else None,
            "pin_drift": drift,
            "patched_layers": patched,
            "image_cve_same_batch": not batch_mismatch,
            "ct_layer_drift": ct_drift,
        },
        "evidence": items,
        "gates": {
            "cve": verdict.get("verdict") if verdict else None,
            "cve_counts": verdict.get("counts") if verdict else None,
            "ct": ct,
            "secret_scan": {k: secrets[k] for k in ("scanned", "findings", "clean")}
                           if secrets else None,
            "hardening": hardening,
            "license": {k: lic_verdict[k] for k in
                        ("verdict", "reason", "components", "unknown", "restricted")}
                       if lic_verdict else None,
        },
        "gaps": gaps,
        "deferred": policy.get("deferred") or [],
        "not_applicable": policy.get("not_applicable") or [],
        "platform_limitation": policy.get("platform_limitation") or [],
    }

    out_file = os.path.join(args.out, "release-manifest.json")
    with open(out_file, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=2)

    # ---- 人看的摘要 ----
    print(f"Release manifest：{os.path.relpath(out_file, REPO)}")
    print(f"日期：{today}    規則：{os.path.relpath(args.policy, REPO)}\n")

    print("證據：")
    for name, ev in items.items():
        if ev:
            print(f"  ✅ {name:18s} {ev['sha256'][:16]}…  {ev['bytes']:>12,} bytes")
        else:
            print(f"  ❌ {name:18s} 找不到")

    print("\n新鮮度：")
    if used is None:
        print("  ❌ 找不到建出這顆 image 的 cooker log —— 無法確認證據對應哪份原始碼")
    elif drift:
        for d in drift:
            print(f"  ❌ {d['repo']}：宣告 {d['declared'][:12]}…"
                  f" 但 build 用的是 {d['built_from'][:12]}…")
    else:
        print("  ✅ 宣告的 pin 與 build 實際使用的 commit 一致")
    for pl in patched:
        print(f"  ✅ {pl['repo']}：宣告的 pin + kas patches "
              f"（{pl['base'][:12]}… → {pl['head'][:12]}…）")
        for c in pl["commits"]:
            print(f"       {c}")
    print(f"  {'❌' if batch_mismatch else '✅'} image 與 CVE 報告"
          f"{'不是' if batch_mismatch else '是'}同一批建置")
    if ct_drift:
        print("  ❌ CT 結果不是這顆 image 跑出來的：")
        for d in ct_drift:
            print(f"       {d['repo']}：CT 用 {d['ct'][:12]}…"
                  f"　image 用 {d['image'][:12]}…")
    elif ct:
        print("  ✅ CT 結果對應這顆 image 的 layer 組合")

    if not manifest["same_build"]:
        print(f"\n⚠️  證據來自 {len(stamps)} 個不同的建置時間戳：{', '.join(stamps)}")
        print("   （sstate 命中的 task 不會重新產生檔案，內容相同但檔名停在上一次）")

    if secrets is None:
        print("\n⚠️  secret scan 沒有執行 —— 找不到 gitleaks（`sudo apt install gitleaks`）")
    else:
        repos = "、".join(f"{x['repo']} {x['commits']} commits" for x in secrets["scanned"])
        mark = "✅ 乾淨" if secrets["clean"] else f"❌ {len(secrets['findings'])} 筆"
        print(f"\nsecret scan（完整歷史）：{mark}    {repos}")
        for f in secrets["findings"]:
            print(f"    {f['repo']}  {f['RuleID']}  {f['File']}:{f['StartLine']}"
                  f"  commit {str(f['Commit'])[:12]}")

    if hardening:
        print(f"\n執行期基準線（{hardening['captured']}）：")
        for b in hardening["ship_blocking"]:
            print(f"    ⚠️  {b['section']}/{b['item']} —— 出貨變體必須改掉")
        rm = hardening["services_to_remove"]
        if rm:
            print("    用不到但仍在跑的服務：" +
                  "、".join(f"{k}（{v}）" for k, v in rm.items()))

    if lic_verdict:
        r = lic_verdict.get("restricted") or []
        print(f"\n授權合規：{lic_verdict['verdict']} —— {lic_verdict['reason']}"
              f"（{lic_verdict['components']} 個元件）")
        for g in r:
            print(f"    ⚠️  {g['id']}：{'、'.join(g['packages'][:6])}")

    print(f"\n閘門：CVE {manifest['gates']['cve']}"
          f"    CT {ct['passed']}/{ct['passed'] + ct['failed']}" if ct else "")

    if gaps:
        print("\n未關閉的缺口（擋 RC，不擋 nightly）：")
        for g in gaps:
            # 動態加入的缺口沒有到期日（它們一修好就自己消失，不需要期限催）
            mark = ("❌ 已過期" if g["expired"]
                    else "—" if g["expires"] == "-"
                    else f"{g['days_left']} 天後到期")
            print(f"  ⬜ {g['id']:28s} owner={g['owner']}  {mark}")
            print(f"     {g['what']}")

    for key, label in (("deferred", "延後"), ("not_applicable", "不適用"),
                       ("platform_limitation", "平台限制")):
        entries = policy.get(key, [])
        if entries:
            print(f"\n{label}：" + "、".join(e["id"] for e in entries))

    print(f"\n{'=' * 62}")
    print(f"頻道：{channel}")
    for r in reasons:
        print(f"  - {r}")
    print("=" * 62)
    return code


if __name__ == "__main__":
    sys.exit(main())
