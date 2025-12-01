#!/usr/bin/env python3
"""
- Fetch F-Droid index
- Filter out language packs, themes, icon packs
- Filter by size (default < 50MB)
- Avoid already downloaded apps
- Download unique apps
"""

import json
import os
import sys
import requests
import time
from typing import Dict, List, Set

MAX_SIZE_MB = 50 
TARGET_COUNT = 200
OUTPUT_DIR = "apks/benign/samples"
FDROID_REPO = "https://f-droid.org/repo"

EXCLUDE_PATTERNS = [
    "languagepack",
    "theme",
    ".icon",
    "arcticons",
    "material_you",
    "daynight",
    ".light",
    ".dark",
    "keyboard.layout",
    "mipmap",
    "skin",
    "wallpaper.pack",
]


def get_existing_packages(output_dir: str) -> Set[str]:
    existing = set()
    if os.path.exists(output_dir):
        for f in os.listdir(output_dir):
            if f.endswith('.apk'):
                pkg = f.rsplit('_', 1)[0]
                existing.add(pkg)
    return existing


def should_exclude(package_id: str) -> bool:
    pkg_lower = package_id.lower()
    for pattern in EXCLUDE_PATTERNS:
        if pattern in pkg_lower:
            return True
    return False


def fetch_fdroid_index() -> Dict:
    url = f"{FDROID_REPO}/index-v2.json"
    resp = requests.get(url, timeout=120)
    resp.raise_for_status()
    return resp.json()


def get_app_info(index: Dict) -> List[Dict]:
    apps = []
    packages = index.get("packages", {})

    for pkg_id, pkg_data in packages.items():
        if should_exclude(pkg_id):
            continue

        versions = pkg_data.get("versions", {})
        if not versions:
            continue

        latest_version = list(versions.values())[0]
        manifest = latest_version.get("manifest", {})

        apk_file = latest_version.get("file", {})
        apk_name = apk_file.get("name", "").lstrip("/")  # Remove leading slash
        size_bytes = apk_file.get("size", 0)
        size_mb = size_bytes / (1024 * 1024)

        if not apk_name or size_mb < 0.5 or size_mb > MAX_SIZE_MB:
            continue

        metadata = pkg_data.get("metadata", {})
        name = metadata.get("name", {})
        if isinstance(name, dict):
            name = name.get("en-US", name.get("en", list(name.values())[0] if name else pkg_id))

        apps.append({
            "package_id": pkg_id,
            "name": name,
            "apk_name": apk_name,
            "size_mb": size_mb,
            "version_code": manifest.get("versionCode", 0),
            "url": f"{FDROID_REPO}/{apk_name}"
        })

    return apps


def download_apk(url: str, output_path: str) -> bool:
    try:
        resp = requests.get(url, timeout=120, stream=True)
        resp.raise_for_status()
        with open(output_path, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        return True
    except Exception as e:
        print(f"  Error: {e}")
        if os.path.exists(output_path):
            os.remove(output_path)
        return False


def main():
    global TARGET_COUNT, MAX_SIZE_MB

    if len(sys.argv) > 1:
        TARGET_COUNT = int(sys.argv[1])
    if len(sys.argv) > 2:
        MAX_SIZE_MB = int(sys.argv[2])

    print(f"Target: {TARGET_COUNT} apps, max size: {MAX_SIZE_MB}MB")

    existing = get_existing_packages(OUTPUT_DIR)
    print(f"Already downloaded: {len(existing)} apps")

    index = fetch_fdroid_index()

    apps = get_app_info(index)
    print(f"Available apps (filtered): {len(apps)}")

    new_apps = [a for a in apps if a["package_id"] not in existing]
    print(f"New apps available: {len(new_apps)}")
    
    import random
    random.seed(42)
    random.shuffle(new_apps)

    new_apps.sort(key=lambda x: abs(x["size_mb"] - 10))

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    downloaded = 0
    failed = 0

    for i, app in enumerate(new_apps[:TARGET_COUNT * 2]):
        if downloaded >= TARGET_COUNT:
            break

        output_path = os.path.join(OUTPUT_DIR, app["apk_name"])

        if os.path.exists(output_path):
            print(f"[{i+1}] SKIP {app['package_id']} (already exists)")
            continue

        print(f"[{downloaded+1}/{TARGET_COUNT}] Downloading {app['package_id']} ({app['size_mb']:.1f}MB)...")

        if download_apk(app["url"], output_path):
            downloaded += 1
        else:
            failed += 1

        time.sleep(0.5)

    print(f"\nDownload complete!")
    print(f"  Downloaded: {downloaded}")
    print(f"  Failed: {failed}")
    print(f"  Total APKs: {len(existing) + downloaded}")


if __name__ == "__main__":
    main()
