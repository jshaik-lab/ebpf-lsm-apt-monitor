#!/usr/bin/env bash
# Build paper/main.pdf — requires MacTeX or TeX Live (pdflatex, bibtex, chktex).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PAPER="$ROOT/paper"

# MacTeX default; extend if you use TinyTeX or another install.
for texbin in /Library/TeX/texbin "$HOME/Library/TinyTeX/bin/universal-darwin"; do
  [[ -d "$texbin" ]] && export PATH="$texbin:$PATH"
done

command -v pdflatex >/dev/null || {
  echo "ERROR: pdflatex not found. Install MacTeX: brew install --cask mactex"
  echo "  Then: export PATH=\"/Library/TeX/texbin:\$PATH\""
  exit 1
}

cd "$PAPER"
echo "=== pdflatex pass 1 ==="
pdflatex -interaction=nonstopmode main.tex
echo "=== bibtex ==="
bibtex main || true
echo "=== pdflatex pass 2 ==="
pdflatex -interaction=nonstopmode main.tex
echo "=== pdflatex pass 3 ==="
pdflatex -interaction=nonstopmode main.tex

if command -v chktex >/dev/null; then
  echo "=== chktex ==="
  chktex -q main.tex || true
fi

if command -v pdfinfo >/dev/null; then
  echo "=== Pages ==="
  pdfinfo main.pdf | grep Pages || true
fi

echo "=== Done: $PAPER/main.pdf ==="
ls -la main.pdf
