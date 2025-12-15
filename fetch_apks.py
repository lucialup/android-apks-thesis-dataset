import requests
import json
import os

INDEX_URL = "https://f-droid.org/repo/index-v2.json"
MIN_SDK = 34 
OUTPUT_FILE = "download_list.txt"
LIMIT = 500

def get_compatible_apks():
    try:
        response = requests.get(INDEX_URL)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"Error downloading fDroid index: {e}")
        return
    
    compatible_links = []
    count = 0

    packages = data.get('packages', {})
    
    for pkg_name, pkg_info in packages.items():
        versions = pkg_info.get('versions', {})

        saved_apk = False

        for version in versions.values():
            if saved_apk: break
            
            manifest = version.get('manifest', {})
            file_info = version.get('file', {})
            
            # Target SDK (Android 14 => SDK 34)
            uses_sdk = manifest.get('usesSdk', {})
            target_sdk = uses_sdk.get('targetSdkVersion', 0)
            
            if target_sdk < MIN_SDK:
                continue

            native_code = file_info.get('nativecode', [])
            
            is_native_x86_64 = 'x86_64' in native_code
            is_universal = not native_code
            
            if is_native_x86_64 or is_universal:
                apk_name = file_info.get('name')
                if apk_name:
                    apk_name = apk_name.lstrip('/')
                    url = f"https://f-droid.org/repo/{apk_name}"
                    compatible_links.append(url)
                    saved_apk = True
                    count += 1
                    
                    type_label = "Native x86_64" if is_native_x86_64 else "Universal (Java)"
                    print(f"[+] Found: {pkg_name} (SDK {target_sdk}, {type_label})")

        if LIMIT and count >= LIMIT:
            break

    with open(OUTPUT_FILE, "w") as f:
        for link in compatible_links:
            f.write(link + "\n")
            
    print(f"\nSuccess! {len(compatible_links)} URLs saved to '{OUTPUT_FILE}'")

if __name__ == "__main__":
    get_compatible_apks()
