# 🛡️ Hybrid AI-Powered Web Application Firewall (ModSecurity + SecBERT AI)

A **Hybrid Web Application Firewall (WAF)** system that combines rule-based detection from **ModSecurity v3 (OWASP CRS)** with deep learning classification powered by **SecBERT AI** to detect and categorize web attacks according to **CAPEC** standards in real time. The project includes an interactive **WAF Dashboard (Vue.js)** and **OWASP Juice Shop** as the protected target application.

## 🏗️ System Architecture (4 Docker Containers)

1. **`waf-nginx-modsec` (`owasp/modsecurity-crs:nginx-alpine`):** Reverse Proxy integrated with ModSecurity v3 and OWASP CRS, intercepting all incoming HTTP traffic on port `80` and generating JSON Audit Logs.
2. **`waf-juice-shop` (`bkimminich/juice-shop`):** Vulnerable web application protected behind the WAF layer.
3. **`waf-backend` (FastAPI + PyTorch + SecBERT AI):** Tails real-time Audit Logs (`log_tailer.py`), executes the hybrid detection pipeline (**ModSecurity Fast-Path** + **SecBERT AI Verification**), stores incident records in SQLite, and exposes REST APIs on port `8000`.
4. **`waf-frontend` (Vue.js + Nginx Alpine):** Web management dashboard for real-time analytics and incident monitoring on port `8080`.

## 📋 Prerequisites

Before deploying the system, ensure your host machine or virtual machine (Ubuntu/Debian, Windows, or macOS) has the following installed:

* **Git** and **Git LFS** *(required to download the AI model weights `model.safetensors` ~319 MB)*
* **Docker Engine** (v20.10+) and **Docker Compose** (v2.0+)

### Quick Installation on Ubuntu / Debian

```bash
# 1. Update system packages and install Git LFS
sudo apt update
sudo apt install -y git git-lfs
git lfs install

# 2. Install Docker Engine & Docker Compose Plugin (if not already installed)
sudo apt install -y docker.io docker-compose-v2 docker-buildx-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

*(Note: Log out and log back in, or run `newgrp docker` to run Docker commands without `sudo`.)*

## 🚀 Installation & Deployment

### Step 1: Clone the Repository and Pull AI Weights

```bash
git clone <YOUR_REPOSITORY_URL> waf-dashboard-project
cd waf-dashboard-project

# Ensure Git LFS pulls the full AI model weights (~319 MB)
git lfs pull
```

### Step 2: Build and Start the Stack with Docker Compose

```bash
# Build images and start all 4 containers in detached mode
docker compose up -d --build
```

*(Tip: If you encounter the warning `Docker Compose is configured to build using Bake, but buildx isn't installed`, run `COMPOSE_BAKE=false docker compose up -d --build` or install `docker-buildx-plugin`.)*

### Step 3: Verify Container Status

Wait approximately **15–20 seconds** for the Backend to load the SecBERT AI model into memory, then check the container status:

```bash
docker compose ps
```

All 4 containers (`waf-nginx-modsec`, `waf-backend`, `waf-frontend`, `waf-juice-shop`) should report their status as **`Up`**.

## 🌐 Port Forwarding Configuration (For VirtualBox VMs)

If you are running Docker inside an Ubuntu VirtualBox VM (using **NAT** networking) and want to access the web interfaces from your **Windows/macOS host browser**, configure Port Forwarding as follows:

1. Open **VirtualBox** $\rightarrow$ Select your VM $\rightarrow$ **Settings** $\rightarrow$ **Network** $\rightarrow$ **Adapter 1 (NAT)** $\rightarrow$ **Advanced** $\rightarrow$ **Port Forwarding**.
2. Add the following rules:

| Name | Protocol | Host IP | Host Port | Guest IP | Guest Port | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **WAF_HTTP** | TCP | *(blank)* | `80` *(or `8081`)* | *(blank)* | `80` | Access OWASP Juice Shop via WAF |
| **Frontend UI** | TCP | *(blank)* | `8080` | *(blank)* | `8080` | Access the WAF Dashboard UI |
| **FastAPI** | TCP | *(blank)* | `8000` | *(blank)* | `8000` | Connect to Backend API & Swagger Docs |
| **SSH** *(optional)* | TCP | *(blank)* | `2223` | *(blank)* | `22` | SSH access from host to VM |

*(Note: If port `80` on Windows is occupied by a system service, set the **Host Port** for `WAF_HTTP` to `8081` while keeping **Guest Port** as `80`.)*

## 🖥️ Accessing the Services & Testing

### 1. Web Interfaces

* **WAF Dashboard (Vue.js):** `http://127.0.0.1:8080/`
* **OWASP Juice Shop (Protected by WAF):** `http://127.0.0.1/` *(or `http://127.0.0.1:8081/`)*
* **Backend API Documentation (FastAPI Swagger):** `http://127.0.0.1:8000/docs`

### 2. End-to-End Traffic Simulation

Open a terminal and send the following `curl` requests to verify both the **ModSecurity Fast-Path** and **SecBERT AI** detection pipelines:

```bash
# 1. Normal Benign Request (ALLOW)
curl -i "http://localhost/"

# 2. SQL Injection Attack (ModSecurity Rule 942 + SecBERT AI -> Code Injection)
curl -i "http://localhost/rest/products/search?q=1'%20UNION%20SELECT%201,2,3--"

# 3. Path Traversal & Vulnerability Scanner (Blocked immediately via ModSecurity Fast-Path)
curl -i -A "Nikto/2.1.6" "http://localhost/?file=../../../../etc/passwd"
```

Refresh **`http://127.0.0.1:8080/`** in your browser to inspect the real-time charts and the **Recent Intercepted Incidents** table.

## 📂 Project Structure

```text
waf-dashboard-project/
├── backend/                  # FastAPI, Log Tailer, SecBERT AI Inference & SQLite DB
│   ├── model/                # SecBERT weights (model.safetensors, config.json, tokenizer)
│   ├── routes/               # REST API endpoints (/api/logs, /api/stats)
│   ├── services/             # ModSecurity audit log parser & real-time log tailer
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/                 # Vue.js 3 + Vite + Chart.js Dashboard UI
│   ├── src/
│   └── Dockerfile
├── nginx/                    # Reverse Proxy, ModSecurity v3 & OWASP CRS configurations
│   ├── default.conf
│   ├── modsec/               # main.conf, modsecurity.conf, unicode.mapping
│   └── modsecurity-crs/      # OWASP Core Rule Set (CRS) rules
└── docker-compose.yml        # Multi-container orchestration file
```

## 🛠️ Useful Management Commands

```bash
# Stream real-time logs from the Backend & SecBERT AI engine
docker logs -f waf-backend

# Stream error logs from Nginx / ModSecurity
docker logs -f waf-nginx-modsec

# Restart only the WAF proxy after modifying rules in ./nginx/
docker compose restart waf-proxy

# Stop and remove all running containers
docker compose down
```