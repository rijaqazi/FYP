import os
import requests

# Server details
base_url = "http://192.168.44.128:5000"
discover_url = f"{base_url}/discover"
username = "admin"
password = "password123"

# Output folder
download_dir = os.path.expanduser("~/Desktop/rules")
os.makedirs(download_dir, exist_ok=True)

# Get JSON response with authentication
print("📡 Fetching file list from server...")
response = requests.get(discover_url, auth=(username, password))
response.raise_for_status()
data = response.json()

files = data.get("files", [])

for entry in files:
    file_name = entry["filename"]
    file_url = f"{base_url}/download/{file_name}"   # ✅ correct endpoint

    file_path = os.path.join(download_dir, file_name)

    # Skip if already downloaded
    if os.path.exists(file_path):
        print(f"⏭️ Skipping {file_name}, already exists.")
        continue

    print(f"⬇️ Downloading {file_name} ...")
    r = requests.get(file_url, auth=(username, password))
    if r.status_code == 200 and b"Authentication required" not in r.content:
        with open(file_path, "wb") as f:
            f.write(r.content)
        print(f"✅ Saved: {file_name}")
    else:
        print(f"⚠️ Failed to download {file_name}: {r.status_code}")

print("\n🎯 All new ZIP files downloaded to:", download_dir)

