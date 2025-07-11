# AngelPit
**A flexible WAF built on mitmproxy with regex-driven filtering, TLS support, and automatic PCAP dumping.**

<p align="center">
  <img src="https://github.com/user-attachments/assets/f8b7a736-8249-41d8-9961-d42f4eae7875" width="300" height="300" alt="AngelPit Logo">
</p>

AngelPit is a lightweight, pluggable **man-in-the-middle proxy** that turns mitmproxy into a **regex-powered Web Application Firewall (WAF)**. It inspects HTTP(S) traffic, parses headers and payloads, and blocks malicious patterns in real time — all while logging traffic and dumping PCAPs for forensics.

## ✨ Features

- ✅ **Regex Header Inspection** – Block or modify requests based on header patterns (User-Agent, Cookies, etc.)
- 🔒 **Full TLS Interception** – Decrypt and inspect HTTPS traffic using mitmproxy’s robust TLS stack.
- 🧠 **Pluggable Addons** – Easily extend logic via custom Python-based mitmproxy addons.
- 📦 **Automatic PCAP Dumps** – Every session is optionally logged as a `.pcap` for offline analysis.
- 🔥 **Realtime Filtering** – Works live, intercepting traffic and applying filters as it flows.
- 📜 **Minimal & Hackable** – Designed for extensibility and simplicity.

## 🧰 Use Cases

- Penetration testing & security research
- Deployable inline WAF for testbeds
- Honeypots or traffic profiling tools
- Teaching tool for regex and protocol filtering

## 🛡️ Disclaimer

AngelPit is a **security research tool**. Do not use it to intercept traffic you don't own or have explicit permission to monitor.
