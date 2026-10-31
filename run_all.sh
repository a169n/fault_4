#!/bin/sh
# One command for the whole submission: tests -> analysis -> figures -> report (.docx) -> PDF (if LibreOffice exists).
set -e
cd "$(dirname "$0")"

PY=python3
if [ -x .venv/bin/python ]; then
  PY=.venv/bin/python
fi

mkdir -p outputs
if PYTHONPATH=src "$PY" -m pytest -q > outputs/test_log.txt 2>&1; then
  cat outputs/test_log.txt
else
  cat outputs/test_log.txt
  echo "Tests failed: build stopped (full log in outputs/test_log.txt)." >&2
  exit 1
fi

PYTHONPATH=src "$PY" -m fault4 all "$@"

SOFFICE=$(command -v soffice || true)
if [ -z "$SOFFICE" ] && [ -x /Applications/LibreOffice.app/Contents/MacOS/soffice ]; then
  SOFFICE=/Applications/LibreOffice.app/Contents/MacOS/soffice
fi
if [ -n "$SOFFICE" ]; then
  "$SOFFICE" --headless --convert-to pdf --outdir report report/Assignment4_Talgatov_Aibyn.docx
else
  echo "PDF export skipped: open report/Assignment4_Talgatov_Aibyn.docx in Word or Pages and export as PDF."
fi
