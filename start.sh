#!/bin/bash

# SIEM Dashboard Startup Script
# Starts backend + frontend together. Just run ./start.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
FRONTEND_DIR="$SCRIPT_DIR/frontend/myapp"
ENV_FILE="$BACKEND_DIR/.env"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}"
echo "=================================================="
echo "  SIEM Dashboard - Security Monitoring Platform"
echo "=================================================="
echo -e "${NC}"

# ── Load .env ──────────────────────────────────────────────────────────────────
if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck source=/dev/null
    source "$ENV_FILE"
    set +a
    echo -e "${GREEN}✓${NC} Loaded environment from backend/.env"
else
    echo -e "${YELLOW}⚠ No backend/.env file found.${NC}"
    echo -e "  Copy ${YELLOW}backend/.env.example${NC} to ${YELLOW}backend/.env${NC} and fill in your values."
    echo -e "  Continuing with defaults (port 8001)..."
fi

# ── Resolve config ─────────────────────────────────────────────────────────────
API_PORT="${API_PORT:-8001}"
API_HOST="${API_HOST:-0.0.0.0}"
FRONTEND_PORT="${VITE_FRONTEND_PORT:-5173}"

# ── Preflight: Python ──────────────────────────────────────────────────────────
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is not installed${NC}"
    exit 1
fi
echo -e "${GREEN}✓${NC} Python 3: $(python3 --version)"

# ── Preflight: Node (auto-switch via nvm if too old) ──────────────────────────
export NVM_DIR="$HOME/.nvm"
# shellcheck source=/dev/null
[ -s "$NVM_DIR/nvm.sh" ] && source "$NVM_DIR/nvm.sh"

if ! command -v node &> /dev/null; then
    echo -e "${RED}Error: Node.js is not installed. Install via: nvm install 22${NC}"
    exit 1
fi

NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
if [ "$NODE_VERSION" -lt 20 ]; then
    echo -e "${YELLOW}⚠ Node $(node -v) is too old. Switching to Node 22 via nvm...${NC}"
    if command -v nvm &> /dev/null; then
        nvm use 22 2>/dev/null || nvm install 22
    else
        echo -e "${RED}nvm not found. Please run: nvm install 22 && nvm use 22${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}✓${NC} Node.js: $(node -v)"

# ── Preflight: directories ─────────────────────────────────────────────────────
if [ ! -d "$FRONTEND_DIR" ]; then
    echo -e "${RED}Error: Frontend not found at $FRONTEND_DIR${NC}"
    exit 1
fi

# ── Backend: venv + deps ───────────────────────────────────────────────────────
cd "$BACKEND_DIR"

if [ ! -d "venv" ]; then
    echo -e "${YELLOW}Creating Python virtual environment...${NC}"
    python3 -m venv venv
fi

source venv/bin/activate

echo -e "${YELLOW}Checking backend dependencies...${NC}"
pip install -q --upgrade pip
pip install -q -r requirements.txt
echo -e "${GREEN}✓${NC} Backend dependencies ready"

# ── Frontend: npm install ──────────────────────────────────────────────────────
cd "$FRONTEND_DIR"

if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}Installing frontend dependencies...${NC}"
    npm install --silent
fi
echo -e "${GREEN}✓${NC} Frontend dependencies ready"

# ── Warn if email not configured ──────────────────────────────────────────────
if [ -z "$SMTP_USERNAME" ] || [ -z "$SMTP_PASSWORD" ]; then
    echo -e "${YELLOW}⚠ Email alerts not configured (set SMTP_USERNAME / SMTP_PASSWORD in .env)${NC}"
fi

# ── Menu ───────────────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}Options:${NC}"
echo "1. Start full stack  (backend + frontend)"
echo "2. Start full stack  (backend + frontend + generate sample data)"
echo "3. Generate sample data only  (backend must already be running)"
echo ""
read -r -p "Choose an option (1-3): " choice

# ── Cleanup on Ctrl+C ─────────────────────────────────────────────────────────
BACKEND_PID=""
FRONTEND_PID=""

cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down...${NC}"
    [ -n "$BACKEND_PID"  ] && kill "$BACKEND_PID"  2>/dev/null; echo -e "${GREEN}✓${NC} Backend stopped"
    [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null; echo -e "${GREEN}✓${NC} Frontend stopped"
    echo -e "${GREEN}All done. Goodbye!${NC}"
    exit 0
}
trap cleanup SIGINT SIGTERM

# ── Helper: start backend ──────────────────────────────────────────────────────
start_backend() {
    echo -e "${BLUE}▶ Starting backend...${NC}"
    cd "$BACKEND_DIR"
    source venv/bin/activate
    python main.py &
    BACKEND_PID=$!

    # Poll until ready
    echo -n "  Waiting for API"
    for i in $(seq 1 30); do
        if curl -s "http://localhost:${API_PORT}/" > /dev/null 2>&1; then
            echo -e " ${GREEN}ready ✓${NC}"
            break
        fi
        sleep 0.5
        echo -n "."
    done
    echo -e "${GREEN}✓${NC} Backend → http://localhost:${API_PORT}"
}

# ── Helper: start frontend ─────────────────────────────────────────────────────
start_frontend() {
    echo -e "${BLUE}▶ Starting frontend...${NC}"
    cd "$FRONTEND_DIR"
    npm run dev -- --port "$FRONTEND_PORT" &
    FRONTEND_PID=$!
    sleep 2   # give Vite a moment to bind the port

    echo ""
    echo -e "  ┌─────────────────────────────────────────────┐"
    echo -e "  │  ${GREEN}🛡  SIEM Dashboard is ready!${NC}               │"
    echo -e "  │                                             │"
    echo -e "  │  Open in browser →  ${CYAN}http://localhost:${FRONTEND_PORT}${NC}   │"
    echo -e "  │  Backend API     →  ${CYAN}http://localhost:${API_PORT}${NC}    │"
    echo -e "  │  Swagger docs    →  ${CYAN}http://localhost:${API_PORT}/docs${NC}│"
    echo -e "  │                                             │"
    echo -e "  │  Press ${RED}Ctrl+C${NC} to stop everything             │"
    echo -e "  └─────────────────────────────────────────────┘"
    echo ""
}

# ── Run chosen option ─────────────────────────────────────────────────────────
case $choice in
    1)
        start_backend
        start_frontend
        wait
        ;;
    2)
        start_backend

        echo -e "${BLUE}▶ Generating sample data...${NC}"
        cd "$BACKEND_DIR"
        python sample_log_generator.py --mode full
        echo -e "${GREEN}✓${NC} Sample data generated"

        start_frontend
        wait
        ;;
    3)
        echo -e "${BLUE}▶ Generating sample data (backend must already be running)...${NC}"
        cd "$BACKEND_DIR"
        source venv/bin/activate
        python sample_log_generator.py --mode full
        echo -e "${GREEN}✓${NC} Done"
        ;;
    *)
        echo -e "${RED}Invalid option. Please choose 1, 2, or 3.${NC}"
        exit 1
        ;;
esac
