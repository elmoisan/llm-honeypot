# 🍯 LLM Honeypot

> A modern, AI-focused honeypot that simulates LLM API endpoints to detect, log, and analyze emerging attack techniques — prompt injection, API key enumeration, jailbreaks, and more.

![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=flat-square)

---

## What is this?

Most honeypots imitate legacy services (SSH, SMB, Telnet). This one is different.

**LLM Honeypot** mimics modern AI API services — fake OpenAI-compatible endpoints, fake model listings, fake API keys — to attract and study attackers targeting AI infrastructure.

Every request is logged, analyzed, and categorized in real time.

---

## ✨ Features

- **Fake LLM endpoints** — `/v1/chat/completions`, `/v1/embeddings`, `/v1/models` (OpenAI-compatible)
- **Prompt injection detection** — catches jailbreaks, role escalation, system prompt extraction attempts
- **API key enumeration tracking** — logs every key tried
- **Rate limit abuse detection** — flags suspicious request spikes
- **IP geolocation** — maps attacker origins in real time
- **Live dashboard** — dark/hacker-style UI with world map and attack feed
- **Structured logs** — JSONL format, easy to parse and analyze
- **One-command deploy** — fully Dockerized

---

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/llm-honeypot.git
cd llm-honeypot

# Configure environment
cp .env.example .env

# Launch with Docker
docker-compose up -d
```

The honeypot will be running on `http://localhost:8000`
The dashboard will be available on `http://localhost:8080`

---

## 📁 Project Structure

```
llm-honeypot/
├── honeypot/               # Core server (FastAPI)
│   ├── main.py             # Entry point
│   ├── endpoints.py        # Fake LLM endpoints
│   ├── detection.py        # Attack detection engine
│   ├── logger.py           # Structured logging
│   └── responses.py        # Realistic fake responses
├── dashboard/              # Visual interface (dark/hacker UI)
├── analysis/               # Analysis & report generation scripts
├── reports/                # Weekly attack analysis reports
├── detection_rules/        # Generated Sigma detection rules
├── logs/                   # Attack logs (JSONL)
├── docker-compose.yml
└── Dockerfile
```

---

## Attack Categories Detected

| Category | Description |
|---|---|
| `prompt_injection` | Attempts to override model instructions |
| `jailbreak` | DAN, roleplay, and constraint bypass attempts |
| `system_prompt_extraction` | Trying to leak the system prompt |
| `role_escalation` | Impersonating admin/system roles |
| `api_key_enumeration` | Brute-forcing API key formats |
| `data_exfiltration` | Attempting to extract internal data |
| `recon` | Probing endpoints and model metadata |

---

## Sample Log Entry

```json
{
  "timestamp": "2026-05-20T14:32:01Z",
  "ip": "45.33.22.11",
  "country": "Netherlands",
  "country_code": "NL",
  "endpoint": "/v1/chat/completions",
  "api_key_tried": "sk-proj-xXxXxXxX",
  "threat_level": "high",
  "categories": ["prompt_injection", "system_prompt_extraction"],
  "user_agent": "python-requests/2.31.0",
  "payload_size": 312
}
```

---

## Reports

Weekly analysis reports are published in [`/reports`](./reports/).

---

## Legal & Ethics

This honeypot is a **purely passive, defensive tool**.
- It does not attack or probe any external system
- It only logs inbound requests made to it voluntarily
- Deploy only on infrastructure you own or have permission to operate
- Never publish raw logs containing real IP addresses

---

## License

MIT — see [LICENSE](./LICENSE)

---

*Built as a cybersecurity research project. Part of an ongoing study on emerging LLM attack techniques.*
