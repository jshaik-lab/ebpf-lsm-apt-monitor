#!/usr/bin/env bash
# Build paper/main.pdf — requires MacTeX or TeX Live (pdflatex, bibtex, chktex).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PAPER="$ROOT/paper"

echo "=== validate paper claims (GCP JSON gate) ==="
python3 "$ROOT/scripts/validate_paper_claims.py"

# MacTeX default; extend if you use TinyTeX or another install.
for texbin in /Library/TeX/texbin "$HOME/Library/TinyTeX/bin/universal-darwin"; do
  [[ -d "$texbin" ]] && export PATH="$texbin:$PATH"
done

command -v pdflatex >/dev/null || command -v tectonic >/dev/null || {
  echo "ERROR: install MacTeX (pdflatex) or tectonic: brew install tectonic"
  exit 1
}

if command -v pdflatex >/dev/null; then
  cd "$PAPER"
  echo "=== pdflatex pass 1 ==="
  pdflatex -interaction=nonstopmode main.tex
  echo "=== bibtex ==="
  bibtex main || true
  echo "=== pdflatex pass 2 ==="
  pdflatex -interaction=nonstopmode main.tex
  echo "=== pdflatex pass 3 ==="
  pdflatex -interaction=nonstopmode main.tex
else
  echo "=== tectonic (pdflatex not found) ==="
  cd "$PAPER"
  tectonic main.tex
fi

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
