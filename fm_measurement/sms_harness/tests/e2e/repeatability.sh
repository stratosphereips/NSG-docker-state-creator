#!/bin/bash
# Repeatability measurement: N consecutive full e2e suite passes.
# Usage: nohup bash repeatability.sh <passes> > /tmp/fm_repeat.log 2>&1 &
cd /home/diego/SCLT/sms_harness
PASSES=${1:-2}
FILES="test_fm11_e2e.py test_fm4_e2e.py test_fm51_e2e.py test_fm61_e2e.py test_fm12_e2e.py test_fm55_e2e.py"
echo "REPEATABILITY RUN start $(date -Is) passes=$PASSES"
for p in $(seq 1 "$PASSES"); do
  echo "===== PASS $p start $(date -Is) ====="
  for f in $FILES; do
    echo "----- pass $p: $f -----"
    python3.12 -m pytest "tests/e2e/$f" -q --tb=line -p no:cacheprovider 2>&1 | tail -6
    echo "rc=$? file=$f pass=$p"
  done
  echo "===== PASS $p end $(date -Is) ====="
done
echo "REPEATABILITY RUN done $(date -Is)"
