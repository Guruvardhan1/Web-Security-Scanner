🛡️ Web Security Scanner
🔍 Overview
The Web Security Scanner is a Python-based tool designed to identify vulnerabilities in web applications. It detects SQL Injection, Cross-Site Scripting (XSS), Open Redirects, and Missing Security Headers.

🚀 Features
✔️ Detects SQL Injection vulnerabilities
✔️ Detects Reflected XSS vulnerabilities
✔️ Checks for Missing Security Headers
✔️ Finds Open Redirect Vulnerabilities
✔️ Saves scan results to scan_results.txt

⚙️ Setup & Installation
1️⃣ Install Dependencies
bash
Copy
Edit
pip install -r requirements.txt
2️⃣ Run the Scanner
bash
Copy
Edit
python scanner.py <target-url>
🔹 Replace <target-url> with the website you want to scan.

📜 Example Usage
bash
Copy
Edit
python scanner.py http://testphp.vulnweb.com
🔍 This will scan the website for SQL Injection, XSS, Open Redirects, and Security Headers.

🎯 How It Works
1️⃣ Sends test payloads to detect vulnerabilities
2️⃣ Analyzes HTTP responses for security weaknesses
3️⃣ Logs results into scan_results.txt

🏆 Credits
Built by Guruvardhan Kothakota as part of a cybersecurity project.
