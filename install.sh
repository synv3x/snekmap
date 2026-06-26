#!/usr/bin/env bash
# SnekMap installer — Interactive edition
# Platforms: Kali/Debian/Ubuntu (apt) · Fedora/RHEL (dnf) · Arch (pacman) · macOS (brew)
# Usage:     ./install.sh [--help]

set -eo pipefail

# ── Terminal info ───────────────────────────────────────────────────────────────
COLS=$(tput cols 2>/dev/null || echo 72)

# ── Colour palette ──────────────────────────────────────────────────────────────
R=$'\033[0m'
BOLD=$'\033[1m'     DIM=$'\033[2m'
RED=$'\033[0;31m'   GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m' BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'  WHITE=$'\033[1;37m'
BBLUE=$'\033[1;34m' BCYAN=$'\033[1;36m'

# ── Message helpers ─────────────────────────────────────────────────────────────
step() { echo -e "  ${BLUE}[→]${R} ${BOLD}$*${R}"; }
ok()   { echo -e "  ${GREEN}[✓]${R} $*"; }
warn() { echo -e "  ${YELLOW}[!]${R} $*"; }
info() { echo -e "  ${CYAN}[i]${R} $*"; }
die()  { echo -e "  ${RED}[✗]${R} $*" >&2; tput cnorm 2>/dev/null || true; exit 1; }

check_cmd() { command -v "$1" &>/dev/null; }
[[ "$EUID" -eq 0 ]] && SUDO="" || SUDO="sudo"

# ── Horizontal rule ─────────────────────────────────────────────────────────────
hr() {
    # hr [color]
    local color="${1:-$CYAN}"
    printf '%s' "$color"
    printf '%.0s─' $(seq 1 "$COLS")
    printf '%s\n' "$R"
}

# ── Spinner ─────────────────────────────────────────────────────────────────────
SPINNER_PID=""
_SF=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')

start_spinner() {
    local msg="$1"
    tput civis 2>/dev/null || true
    (
        local i=0
        while true; do
            printf "\r  ${CYAN}${_SF[$i]}${R}  ${DIM}%-50s${R}" "$msg"
            i=$(( (i + 1) % 10 ))
            sleep 0.08
        done
    ) &
    SPINNER_PID=$!
}

stop_spinner() {
    if [[ -n "$SPINNER_PID" ]]; then
        kill "$SPINNER_PID" 2>/dev/null || true
        wait "$SPINNER_PID" 2>/dev/null || true
        SPINNER_PID=""
        printf "\r\033[K"
    fi
    tput cnorm 2>/dev/null || true
}

trap 'stop_spinner; tput cnorm 2>/dev/null || true' EXIT INT TERM

# ── Animated banner ─────────────────────────────────────────────────────────────
print_banner() {
    local art=(
        "███████╗███╗  ██╗███████╗██╗  ██╗███╗   ███╗ █████╗ ██████╗ "
        "██╔════╝████╗ ██║██╔════╝██║ ██╔╝████╗ ████║██╔══██╗██╔══██╗"
        "███████╗██╔██╗██║█████╗  █████╔╝ ██╔████╔██║███████║██████╔╝"
        "╚════██║██║╚████║██╔══╝  ██╔═██╗ ██║╚██╔╝██║██╔══██║██╔═══╝ "
        "███████║██║ ╚███║███████╗██║  ██╗██║ ╚═╝ ██║██║  ██║██║     "
        "╚══════╝╚═╝  ╚══╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     "
    )
    local colors=("$BLUE" "$BBLUE" "$BCYAN" "$BCYAN" "$BBLUE" "$BLUE")
    local art_w=65

    local pad=""
    if (( COLS > art_w + 2 )); then
        pad="$(printf '%*s' $(( (COLS - art_w) / 2 )) '')"
    fi

    echo ""
    for i in "${!art[@]}"; do
        echo -e "${colors[$i]}${pad}${art[$i]}${R}"
        sleep 0.055
    done
    echo ""
}

# ── Typewriter line ─────────────────────────────────────────────────────────────
typewrite() {
    local msg="$1" delay="${2:-0.025}"
    local i
    for (( i = 0; i < ${#msg}; i++ )); do
        printf '%s' "${msg:$i:1}"
        sleep "$delay"
    done
    printf '\n'
}

# ── Section header ──────────────────────────────────────────────────────────────
section() {
    local title="$1" n="$2" total="${3:-$TOTAL_STEPS}"
    echo ""
    hr "$BBLUE"
    printf "  ${BOLD}${CYAN}%s${R}" "$title"
    [[ -n "$n" ]] && printf "  ${DIM}[Step %s / %s]${R}" "$n" "$total"
    printf '\n'
    hr "$BBLUE"
    echo ""
}

# ── Package manager state ────────────────────────────────────────────────────────
_PKG_UPDATED=false
PKG_MANAGER=""
PKG_INSTALL=""

sys_install() {
    if [[ "$_PKG_UPDATED" == "false" ]]; then
        case "$PKG_MANAGER" in
            apt)
                start_spinner "Updating apt package index..."
                $SUDO apt-get update -qq >/dev/null 2>&1 || true
                stop_spinner; ok "apt index updated"
                ;;
            pacman)
                start_spinner "Syncing pacman database..."
                $SUDO pacman -Sy --noconfirm >/dev/null 2>&1 || true
                stop_spinner; ok "pacman database synced"
                ;;
        esac
        _PKG_UPDATED=true
    fi

    for pkg in "$@"; do
        start_spinner "Installing ${pkg}..."
        if eval "$PKG_INSTALL $pkg" >/dev/null 2>&1; then
            stop_spinner; ok "${BOLD}${pkg}${R} installed"
        else
            stop_spinner; die "Failed to install $pkg. Install it manually and re-run."
        fi
    done
}

# ── Help ─────────────────────────────────────────────────────────────────────────
show_help() {
    cat << 'EOF'
SnekMap Installer

USAGE
    ./install.sh          Interactive installation
    ./install.sh --help   Show this help and exit

SUPPORTED PLATFORMS
    Kali Linux / Debian / Ubuntu    apt-get
    Fedora / RHEL / CentOS Stream   dnf
    Arch Linux / Manjaro            pacman
    macOS 12+                       Homebrew

WHAT GETS INSTALLED
  System packages (via your OS package manager, if not already present):
    nmap          port scanner — required
    git           version control — required
    python3       Python 3.9+ — required
    python3-venv  venv module — required on Debian/Kali

  Python packages (isolated inside .venv — system Python untouched):
    python-nmap   Python interface to nmap
    requests      HTTPS calls to the NIST NVD API
    rich          Terminal formatting and progress UI
    reportlab     PDF report generation

  Global command: /usr/local/bin/snekmap  (or ~/.local/bin/snekmap)
  Cache directory: ~/.snekmap/

IDEMPOTENCY
    Safe to re-run. Existing tools, .venv, and cache are detected and
    skipped or updated — nothing is overwritten from scratch.

NVD API KEY (optional)
    Raises CVE lookup limits from 5 req/30 s to 50 req/30 s (10× faster).
    The installer prompts for one with a 30-second timeout.
    Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

UNINSTALL
    sudo rm -f /usr/local/bin/snekmap   # or: rm -f ~/.local/bin/snekmap
    rm -rf .venv ~/.snekmap

EOF
    exit 0
}
# ── Thank You message ──────────────────────────────────────────────────────────
echo ""
thank_msg="╭─ Thank You For Using SnekMap ─╮"
thank_pad=$(( (COLS - ${#thank_msg}) / 2 ))
printf '%*s%s\n' "$thank_pad" '' "$thank_msg"
printf '%*s%s\n' "$thank_pad" '' "│  Installation in progress...    │"
printf '%*s%s\n' "$thank_pad" '' "╰────────────────────────────────╯"
sleep 2
echo ""

[[ "${1:-}" == "--help" || "${1:-}" == "-h" ]] && show_help

# ════════════════════════════════════════════════════════════════════════════════
#  INSTALLATION BEGINS
# ════════════════════════════════════════════════════════════════════════════════
TOTAL_STEPS=8

clear
print_banner

# Centred subtitle
sub="v0.1.0  ·  Network Reconnaissance & Vulnerability Assessment"
sub_pad=""
(( COLS > ${#sub} + 4 )) && sub_pad="$(printf '%*s' $(( (COLS - ${#sub}) / 2 )) '')"
hr "$CYAN"
printf '%s' "$sub_pad"
typewrite "${DIM}${sub}${R}" 0.018
hr "$CYAN"
echo ""
echo -e "  ${DIM}Run ${YELLOW}./install.sh --help${R}${DIM} for full options and uninstall steps.${R}"
echo ""

# Welcome prompt (interactive terminal only)
if [[ -t 0 ]]; then
    echo -ne "  ${CYAN}▶${R}  Press ${BOLD}Enter${R} to begin installation… "
    read -r
    echo ""
fi

# ── STEP 1: Platform detection ────────────────────────────────────────────────
section "Platform Detection" 1

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "Tool directory: ${BOLD}${INSTALL_DIR}${R}"
echo ""

if check_cmd apt-get; then
    PKG_MANAGER="apt"; PKG_INSTALL="$SUDO apt-get install -y -qq"
    ok "Package manager: ${BOLD}apt-get${R}  ${DIM}(Debian / Kali / Ubuntu)${R}"
elif check_cmd dnf; then
    PKG_MANAGER="dnf"; PKG_INSTALL="$SUDO dnf install -y -q"
    ok "Package manager: ${BOLD}dnf${R}  ${DIM}(Fedora / RHEL)${R}"
elif check_cmd pacman; then
    PKG_MANAGER="pacman"; PKG_INSTALL="$SUDO pacman -S --noconfirm --needed"
    ok "Package manager: ${BOLD}pacman${R}  ${DIM}(Arch / Manjaro)${R}"
elif check_cmd brew; then
    PKG_MANAGER="brew"; PKG_INSTALL="brew install"
    ok "Package manager: ${BOLD}Homebrew${R}  ${DIM}(macOS)${R}"
else
    die "No supported package manager found (apt-get / dnf / pacman / brew)."
fi
echo ""

# ── STEP 2: System prerequisites ─────────────────────────────────────────────
section "System Prerequisites" 2

# Python 3.9+
step "Checking for Python 3.9+..."
PY_CMD=""
for candidate in python3 python3.13 python3.12 python3.11 python3.10 python3.9 python; do
    if check_cmd "$candidate"; then
        if "$candidate" -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" 2>/dev/null; then
            PY_CMD="$candidate"
            ok "Found: ${BOLD}$("$PY_CMD" --version 2>&1)${R}"
            break
        fi
    fi
done

if [[ -z "$PY_CMD" ]]; then
    warn "Python 3.9+ not found — installing via ${PKG_MANAGER}..."
    case "$PKG_MANAGER" in
        apt)    sys_install python3 python3-venv python3-full ;;
        dnf)    sys_install python3 ;;
        pacman) sys_install python ;;
        brew)   sys_install python3 ;;
    esac
    PY_CMD="python3"
    "$PY_CMD" -c "import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)" 2>/dev/null \
        || die "Installed Python is still < 3.9: $("$PY_CMD" --version 2>&1)"
    ok "Python installed: ${BOLD}$("$PY_CMD" --version 2>&1)${R}"
fi

# python3-venv
echo ""
step "Checking for python3 venv module..."
if "$PY_CMD" -m venv --help &>/dev/null; then
    ok "venv module available"
else
    case "$PKG_MANAGER" in
        apt) sys_install python3-venv python3-full ;;
        dnf) sys_install python3-virtualenv ;;
        *)   die "python3 venv module missing. Run: $PKG_MANAGER install python3-venv" ;;
    esac
    "$PY_CMD" -m venv --help &>/dev/null \
        || die "venv still unavailable after install."
    ok "venv module available"
fi

# nmap
echo ""
step "Checking for nmap..."
if check_cmd nmap; then
    ok "nmap: ${DIM}$(nmap --version 2>&1 | head -1)${R}"
else
    sys_install nmap
fi

# git
echo ""
step "Checking for git..."
if check_cmd git; then
    ok "git: ${DIM}$(git --version 2>&1)${R}"
else
    sys_install git
fi
echo ""

# ── STEP 3: Cache directory ───────────────────────────────────────────────────
section "Cache Directory" 3

CACHE_DIR="$HOME/.snekmap"
step "Cache directory: ${BOLD}${CACHE_DIR}${R}"
if [[ -d "$CACHE_DIR" ]]; then
    ok "Already exists — skipping"
else
    mkdir -p "$CACHE_DIR"
    ok "Created ${BOLD}$CACHE_DIR${R}"
fi
echo ""

# ── STEP 4: Python virtual environment ───────────────────────────────────────
section "Python Environment (venv)" 4

VENV_DIR="$INSTALL_DIR/.venv"
VENV_PY="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

if [[ -d "$VENV_DIR" && -x "$VENV_PIP" ]]; then
    ok "Virtual environment exists — refreshing packages"
else
    start_spinner "Creating virtual environment at ${VENV_DIR}..."
    "$PY_CMD" -m venv "$VENV_DIR" \
        || { stop_spinner; die "Failed to create virtual environment. Try: $PY_CMD -m venv $VENV_DIR"; }
    stop_spinner
    ok "Virtual environment created"
fi

echo ""
start_spinner "Upgrading pip..."
"$VENV_PIP" install --quiet --upgrade pip
stop_spinner; ok "pip up to date"

echo ""
start_spinner "Installing Python packages from requirements.txt..."
"$VENV_PIP" install --quiet -r "$INSTALL_DIR/requirements.txt" \
    || { stop_spinner; die "pip install failed. Check requirements.txt and your network."; }
stop_spinner; ok "Python dependencies installed"
echo ""

# ── STEP 5: Global command ────────────────────────────────────────────────────
section "Global Command" 5

# Build wrapper (variables expanded now; $@ is literal — intentional)
WRAPPER="$(printf '#!/bin/bash\nexec "%s" "%s" "$@"\n' "$VENV_PY" "$INSTALL_DIR/snekmap.py")"

install_wrapper() {
    local dest="$1"
    printf '%s\n' "$WRAPPER" | $SUDO tee "$dest" >/dev/null 2>&1 \
        && $SUDO chmod +x "$dest" 2>/dev/null
}

LAUNCH_CMD="snekmap"

if install_wrapper "/usr/local/bin/snekmap"; then
    ok "Global command installed: ${BOLD}/usr/local/bin/snekmap${R}"
else
    LOCAL_BIN="$HOME/.local/bin"
    mkdir -p "$LOCAL_BIN"
    if install_wrapper "$LOCAL_BIN/snekmap"; then
        ok "User command installed: ${BOLD}$LOCAL_BIN/snekmap${R}"
        if [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
            warn "\$HOME/.local/bin is not on your PATH"
            info "Add to ~/.bashrc or ~/.zshrc:"
            echo ""
            echo -e "    ${YELLOW}export PATH=\"\$HOME/.local/bin:\$PATH\"${R}"
            echo ""
        fi
    else
        die "Could not write wrapper to /usr/local/bin or ~/.local/bin. Check permissions."
    fi
fi
echo ""

# ── STEP 6: Man page ──────────────────────────────────────────────────────────
section "Man Page" 6

MAN_SRC="$INSTALL_DIR/snekmap.1"
if [[ -f "$MAN_SRC" ]]; then
    MAN_INSTALLED=false
    for man_dir in "/usr/share/man/man1" "/usr/local/share/man/man1" "$HOME/.local/share/man/man1"; do
        if $SUDO mkdir -p "$man_dir" 2>/dev/null \
           && $SUDO cp "$MAN_SRC" "$man_dir/snekmap.1" 2>/dev/null; then
            $SUDO mandb -q 2>/dev/null || true
            ok "Man page installed → ${BOLD}$man_dir/snekmap.1${R}"
            info "Run: ${YELLOW}man snekmap${R}"
            MAN_INSTALLED=true
            break
        fi
    done
    if [[ "$MAN_INSTALLED" == "false" ]]; then
        warn "Could not install man page — permission denied"
        info "Install manually: ${YELLOW}sudo cp snekmap.1 /usr/share/man/man1/ && sudo mandb${R}"
        info "Or read locally:  ${YELLOW}man ./snekmap.1${R}"
    fi
else
    warn "snekmap.1 not found — skipping man page"
fi
echo ""

# ── STEP 7: NVD API key ───────────────────────────────────────────────────────
section "NVD API Key (Optional)" 7

info "A free NVD API key unlocks ${BOLD}10× faster${R} CVE lookups  ${DIM}(50 req/30 s vs 5 req/30 s)${R}."
info "Get one free at: ${CYAN}https://nvd.nist.gov/developers/request-an-api-key${R}"
echo ""

SHELL_RC=""
[[ -f "$HOME/.zshrc"  ]] && SHELL_RC="$HOME/.zshrc"
[[ -f "$HOME/.bashrc" ]] && SHELL_RC="$HOME/.bashrc"

NVD_KEY=""
if [[ -t 0 ]]; then
    echo -ne "  ${YELLOW}[?]${R} Enter NVD_API_KEY  ${DIM}(30 s timeout — Enter to skip)${R}: "
    read -r -t 30 NVD_KEY 2>/dev/null || true
    echo ""
else
    info "Non-interactive session — skipping NVD API key prompt"
fi

if [[ -n "$NVD_KEY" ]]; then
    export NVD_API_KEY="$NVD_KEY"
    if [[ -n "$SHELL_RC" ]]; then
        grep -v "^export NVD_API_KEY=" "$SHELL_RC" > "${SHELL_RC}.tmp" \
            && mv "${SHELL_RC}.tmp" "$SHELL_RC"
        echo "export NVD_API_KEY=\"$NVD_KEY\"" >> "$SHELL_RC"
        ok "NVD_API_KEY saved to ${BOLD}$SHELL_RC${R}"
        info "Run ${YELLOW}source $SHELL_RC${R} or open a new terminal to activate it."
    else
        warn "No shell profile found — add manually:"
        echo ""
        echo -e "    ${YELLOW}export NVD_API_KEY=\"$NVD_KEY\"${R}"
        echo ""
    fi
else
    warn "No key provided — unauthenticated rate limit applies  ${DIM}(slower, fully functional)${R}"
fi
echo ""

# ── STEP 8: Connectivity test ─────────────────────────────────────────────────
section "Connectivity Test" 8

NVD_PROBE="https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
HTTP_CODE=""

start_spinner "Testing NVD API reachability..."
if check_cmd curl; then
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$NVD_PROBE" 2>/dev/null || true)
elif check_cmd wget; then
    HTTP_CODE=$(wget -q --spider --server-response --timeout=8 "$NVD_PROBE" 2>&1 \
                | awk '/HTTP\//{print $2}' | tail -1 || true)
fi
stop_spinner

case "$HTTP_CODE" in
    200) ok "NVD API reachable  ${DIM}(HTTP 200)${R}" ;;
    "")  warn "Could not test — curl/wget unavailable or no network" ;;
    429) warn "NVD API rate-limited (HTTP 429) — backoff will apply automatically" ;;
    *)   warn "NVD API returned HTTP $HTTP_CODE — CVE data may be limited on this network" ;;
esac
echo ""

# ── Done ─────────────────────────────────────────────────────────────────────
sleep 0.15
hr "$GREEN"
echo ""
printf "  ${GREEN}${BOLD}✓  SnekMap installation complete!${R}\n"
echo ""
hr "$GREEN"
echo ""

echo -e "  ${BOLD}Get started:${R}"
echo ""
echo -e "  ${YELLOW}${BOLD}  $LAUNCH_CMD <target>${R}                 ${DIM}scan a host${R}"
echo -e "  ${YELLOW}${BOLD}  $LAUNCH_CMD 192.168.1.0/24 -f${R}       ${DIM}/24 network sweep (fast mode)${R}"
echo -e "  ${YELLOW}${BOLD}  sudo $LAUNCH_CMD 10.0.0.1 -d${R}        ${DIM}deep scan + OS detection${R}"
echo -e "  ${YELLOW}${BOLD}  $LAUNCH_CMD 10.0.0.1 --export all${R}   ${DIM}export all report formats${R}"
echo -e "  ${YELLOW}${BOLD}  $LAUNCH_CMD --help${R}                   ${DIM}full option reference${R}"
echo ""

cat << 'QUICKREF'
  ┌──────────────────────────────────────────────────────────┐
  │  QUICK REFERENCE                                         │
  │                                                          │
  │  Modes:   (default)  top 1000 ports + CVE + all checks   │
  │           -f         fast  — top 100 ports               │
  │           -d         deep  — all 65535 ports             │
  │           --no-cve   skip CVE lookup (offline / fast)    │
  │                                                          │
  │  Output:  --export html | pdf | json | csv | all         │
  │           -o DIR     save reports to DIR                 │
  │           -q         quiet (no banner, no spinners)      │
  │                                                          │
  │  Help:    snekmap --help    full option reference        │
  └──────────────────────────────────────────────────────────┘
QUICKREF
echo ""
