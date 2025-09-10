# Npm-affected-Version-error-ex-1.3.3-Fixed

This repository demonstrates how to integrate a **malware scan into `pnpm install`** using a custom `.pnpmfile.cjs` hook and a JSON-based malware list.  
It is intended as an example setup to detect and block malicious npm packages during dependency installation.

---

## 📂 Repository Contents

- **`.pnpmfile.cjs`**  
  Adds a post-resolution hook (`afterAllResolved`) that scans dependencies against a malware list.  

- **`malware_predictions.json`**  
  Contains a list of flagged packages and versions that should be blocked.  

---

## 🚀 Setup

1. Copy the two files into your project’s `frontend` folder:

```bash
/project/frontend
├── .pnpmfile.cjs
└── malware_predictions.json
```bash

Install dependencies
From inside the frontend folder, run:

pnpm install

During installation, pnpm will use .pnpmfile.cjs to check all resolved dependencies against malware_predictions.json.

🔍 How It Works

Every package processed is collected by the hook (readPackage).
After resolution (afterAllResolved), the malware list is loaded.
Installed dependencies are checked against the list:
Exact match: package_name[version]
Wildcard match: package_name[*]
If malware is found, the installation fails with an error message.


## ✅ Expected Behavior

If no dependencies match the malware list →
No malware detected in dependencies.
If a dependency matches →
Malware detected in the following packages:
- some-package[1.3.3]: MALWARE

The installation will abort.


## 📌 Notes

This setup works in Node.js 16 (uses https or local JSON).

For production, you may want to fetch malware_predictions.json dynamically (it updates frequently).

You can customize malware_predictions.json to add your own allowlist/denylist of packages.
