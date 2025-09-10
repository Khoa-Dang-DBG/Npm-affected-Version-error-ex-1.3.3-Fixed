This repository demonstrates how to use .pnpmfile.cjs hooks to scan installed dependencies against a known list of malware-affected npm package versions.

It includes:

.pnpmfile.cjs → adds a post-resolution hook (afterAllResolved) to scan dependencies.

malware_predictions.json → JSON file containing flagged packages/versions.

📥 Setup

Download both files
Copy the following files into your project’s frontend folder:

/project/frontend
├── .pnpmfile.cjs
└── malware_predictions.json

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


✅ Expected Behavior

If no dependencies match the malware list →
No malware detected in dependencies.
If a dependency matches →
Malware detected in the following packages:
- some-package[1.3.3]: MALWARE

The installation will abort.


📌 Notes

This setup works in Node.js 16 (uses https or local JSON).

For production, you may want to fetch malware_predictions.json dynamically (it updates frequently).

You can customize malware_predictions.json to add your own allowlist/denylist of packages.
