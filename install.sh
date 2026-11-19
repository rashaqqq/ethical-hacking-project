#!/usr/bin/env bash
set -e

CYAN='\033[0;36m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

REPO_URL="https://github.com/rashaqqq/ethical-hacking-project.git"
INSTALL_DIR="$HOME/securescope-ai"

echo -e "${CYAN}🦉 Installing SecureScope AI...${NC}"

if [ -d "$INSTALL_DIR" ]; then
    echo -e "${GREEN}✓ Updating existing installation in $INSTALL_DIR...${NC}"
    cd "$INSTALL_DIR" && git pull -q
else
    echo -e "${GREEN}✓ Cloning repository...${NC}"
    git clone -q "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

echo -e "${GREEN}✓ Setting up isolated Python environment...${NC}"
python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt

mkdir -p "$HOME/.local/bin"
cat << 'INNER' > "$HOME/.local/bin/securescope"
#!/usr/bin/env bash
cd "$HOME/securescope-ai"
source .venv/bin/activate
python src/run_full.py "$@"
INNER
chmod +x "$HOME/.local/bin/securescope"

for rc in "$HOME/.zshrc" "$HOME/.bashrc"; do
    if [ -f "$rc" ] && ! grep -q '.local/bin' "$rc"; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rc"
    fi
done

echo ""
echo -e "${CYAN}${BOLD}"
cat << "BANNER"
 ____                            ____                        _    ___ 
/ ___|  ___  ___ _   _ _ __ ___ / ___|  ___ ___  _ __   ___ / \  |_ _|
\___ \ / _ \/ __| | | | '__/ _ \\___ \ / __/ _ \| '_ \ / _ \ _ \  | | 
 ___) |  __/ (__| |_| | | |  __/ ___) | (_| (_) | |_) |  __/ ___ \ | | 
|____/ \___|\___|\__,_|_|  \___|____/ \___\___/| .__/ \___/_/   \_\___|
                                               |_|                     
BANNER
echo -e "${NC}"
echo -e "${BOLD}Human-in-the-Loop Ethical Vulnerability Assessment Assistant${NC}"
echo ""
echo "To get started:"
echo ""
echo -e "  ${CYAN}1. Set your environment:${NC}"
echo "     cd ~/securescope-ai"
echo "     echo \"GROQ_API_KEY='your-groq-api-key'\" > .env"
echo ""
echo -e "  ${CYAN}2. Run a security assessment:${NC}"
echo "     securescope --max 5"
echo ""
echo -e "Repository: ${CYAN}https://github.com/rashaqqq/ethical-hacking-project${NC}"
echo ""
echo -e "${YELLOW}➜ Run: source ~/.zshrc  (or open a new terminal)${NC}"
