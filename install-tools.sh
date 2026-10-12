#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Spidy companion toolkit installer (Linux / macOS)
#
# Installs common open-source recon / scanning tools INTO ./tools (self-
# contained), using official prebuilt binaries from GitHub releases, pip, and
# git. No sudo required. Safe to re-run — it skips anything already installed.
#
# These are third-party tools downloaded from their official repositories.
# Review this script before running it, and only scan systems you are
# authorized to test.
#
# Usage:   bash install-tools.sh
# After:   export PATH="$PWD/tools/bin:$PATH"   (the script prints this)
# ---------------------------------------------------------------------------
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS="$ROOT/tools"; BIN="$TOOLS/bin"; SRC="$TOOLS/src"; VENV="$TOOLS/venv"
mkdir -p "$BIN" "$SRC"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"          # linux | darwin
case "$(uname -m)" in
  x86_64|amd64)  GOARCH=amd64;  RARCH=x86_64 ;;
  aarch64|arm64) GOARCH=arm64;  RARCH=aarch64 ;;
  *)             GOARCH=amd64;  RARCH=x86_64 ;;
esac

OK=(); SKIP=()
have(){ command -v "$1" >/dev/null 2>&1; }
ok(){ OK+=("$1"); }
skip(){ SKIP+=("$1 — $2"); echo "   skip: $1 ($2)"; }

# Extract a downloaded archive at $1 into dir $2 (zip via python3, tar via tar).
extract(){
  case "$1" in
    *.zip)          python3 -m zipfile -e "$1" "$2" 2>/dev/null ;;
    *.tar.gz|*.tgz) tar xzf "$1" -C "$2" ;;
    *.gz)           gunzip -c "$1" > "$2/payload.bin" ;;
    *)              cp "$1" "$2/payload.bin" ;;
  esac
}

# gh_install <owner/repo> <asset-name-regex> <binary-name>
gh_install(){
  local repo="$1" rx="$2" bin="$3" url tmp found
  if [ -x "$BIN/$bin" ]; then ok "$bin (already present)"; return; fi
  echo ">> $bin  ($repo)"
  url=$(curl -fsSL --retry 2 "https://api.github.com/repos/$repo/releases/latest" 2>/dev/null \
        | grep -oE '"browser_download_url": *"[^"]+"' | cut -d'"' -f4 \
        | grep -iE "$rx" | head -1)
  [ -z "$url" ] && { skip "$bin" "no release asset matched"; return; }
  tmp=$(mktemp -d)
  # Keep the real filename so extract() can tell zip from tarball from raw binary.
  local pkg; pkg="$tmp/$(basename "${url%%\?*}")"
  if curl -fsSL --retry 2 "$url" -o "$pkg"; then
    extract "$pkg" "$tmp"
    # Some projects double-wrap (e.g. a .tar.gz inside a .zip); unwrap one more level.
    for nested in "$tmp"/*.tar.gz "$tmp"/*.tgz "$tmp"/*.zip; do
      [ -f "$nested" ] && [ "$nested" != "$pkg" ] && extract "$nested" "$tmp"
    done
    found=$(find "$tmp" -type f -name "$bin" ! -samefile "$pkg" 2>/dev/null | head -1)
    [ -z "$found" ] && [ -f "$tmp/payload.bin" ] && found="$tmp/payload.bin"
    if [ -n "$found" ]; then install -m 0755 "$found" "$BIN/$bin"; ok "$bin"; else skip "$bin" "binary not found in archive"; fi
  else skip "$bin" "download failed"; fi
  rm -rf "$tmp"
}

echo "== Prebuilt binaries (Go / Rust) =="
gh_install projectdiscovery/nuclei      "nuclei_.*_${OS}_${GOARCH}\.zip"      nuclei
gh_install projectdiscovery/httpx       "httpx_.*_${OS}_${GOARCH}\.zip"       httpx
gh_install projectdiscovery/katana      "katana_.*_${OS}_${GOARCH}\.zip"      katana
gh_install projectdiscovery/subfinder   "subfinder_.*_${OS}_${GOARCH}\.zip"   subfinder
gh_install projectdiscovery/naabu       "naabu_.*_${OS}_${GOARCH}\.zip"       naabu
gh_install projectdiscovery/dnsx        "dnsx_.*_${OS}_${GOARCH}\.zip"        dnsx
gh_install lc/gau                       "gau_.*_${OS}_${GOARCH}\.tar\.gz"      gau
gh_install ffuf/ffuf                    "ffuf_.*_${OS}_${GOARCH}\.tar\.gz"     ffuf
gh_install OJ/gobuster                  "gobuster_.*(${OS}|${OS^})_(${GOARCH}|${RARCH})\.(tar\.gz|zip)"  gobuster
gh_install owasp-amass/amass            "amass_${OS}_${GOARCH}\.tar\.gz"        amass
gh_install epi052/feroxbuster           "${RARCH}-.*${OS}-feroxbuster\.(tar\.gz|zip)"  feroxbuster
gh_install bee-san/RustScan             ".*${RARCH}.*${OS}.*\.(tar\.gz|zip)"   rustscan

if [ -x "$BIN/nuclei" ]; then
  echo "== Fetching nuclei templates (first time only, ~30s) =="
  "$BIN/nuclei" -update-templates -disable-update-check >/dev/null 2>&1 && echo "   templates ready" || echo "   (templates will download on first scan)"
fi

echo "== Python tools (wafw00f, sslyze) =="
if python3 -m venv "$VENV" 2>/dev/null; then
  if "$VENV/bin/pip" -q install --upgrade pip wafw00f sslyze dirsearch >/dev/null 2>&1; then
    for t in wafw00f sslyze dirsearch; do [ -x "$VENV/bin/$t" ] && { ln -sf "$VENV/bin/$t" "$BIN/$t"; ok "$t"; }; done
  else skip "wafw00f/sslyze" "pip install failed"; fi
else skip "wafw00f/sslyze" "python venv unavailable (apt install python3-venv)"; fi

echo "== Script tools (nikto, testssl.sh) =="
if have perl; then
  [ -d "$SRC/nikto" ] || git clone -q --depth 1 https://github.com/sullo/nikto "$SRC/nikto" 2>/dev/null
  if [ -f "$SRC/nikto/program/nikto.pl" ]; then
    if ! perl -I "$TOOLS/perl5/lib/perl5" -MXML::Writer -e 1 2>/dev/null; then
      python3 "$ROOT/scripts/install-nikto-deps.py" || echo "   XML::Writer installation failed; Nikto needs repair."
    fi
    printf '#!/usr/bin/env bash\nexec perl -I "%s/perl5/lib/perl5" "%s/program/nikto.pl" "$@"\n' "$TOOLS" "$SRC/nikto" > "$BIN/nikto"
    chmod +x "$BIN/nikto"
    if "$BIN/nikto" -Version; then ok nikto; else skip nikto "local startup check failed"; fi
  else skip nikto "clone failed"; fi
else skip nikto "perl not installed"; fi
[ -d "$SRC/testssl" ] || git clone -q --depth 1 https://github.com/drwetter/testssl.sh "$SRC/testssl" 2>/dev/null
if [ -f "$SRC/testssl/testssl.sh" ]; then ln -sf "$SRC/testssl/testssl.sh" "$BIN/testssl.sh"; ok testssl.sh; else skip testssl.sh "clone failed"; fi

echo "== Needs extra runtimes (not auto-installed) =="
have gem  || skip "wpscan / whatweb" "need Ruby — sudo apt install ruby && gem install wpscan; whatweb via apt"
have masscan || skip "masscan" "build from source or sudo apt install masscan"

echo
echo "================= SUMMARY ================="
printf 'Installed (%d): %s\n' "${#OK[@]}" "${OK[*]:-none}"
if [ "${#SKIP[@]}" -gt 0 ]; then printf '\nSkipped (%d):\n' "${#SKIP[@]}"; printf '  - %s\n' "${SKIP[@]}"; fi
echo
echo "Add the tools to your PATH for this shell:"
echo "    export PATH=\"$BIN:\$PATH\""
echo "Make it permanent:  echo 'export PATH=\"$BIN:\$PATH\"' >> ~/.bashrc"
echo "Everything lives in: $TOOLS   (delete that folder to uninstall)"
