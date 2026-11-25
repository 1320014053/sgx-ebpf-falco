set -euo pipefail
cd /root/c7t-xlarge-ship
export LD_LIBRARY_PATH="$PWD/runtime/usr/lib/x86_64-linux-gnu"
b=/root/c7t-xlarge-ship/src/results/aliyun-c7t-xlarge/runs/20261125T130226Z-13d592774b63
S=$PWD/src/results/aliyun-c7t-xlarge/scripts
cd "$b"
exec 9>".run-all.lock"
flock -n 9
sha256sum --quiet -c evidence/supplement/e2-before.sha256
head -c "$(stat -c %s evidence/supplement/trials-before.csv)" trials.csv | cmp - evidence/supplement/trials-before.csv
python3 "$S/summarize.py" "$b" > evidence/supplement/summarize.log
touch summary/.complete
python3 evidence/supplement/summarize-background.py
find . -type f ! -name SHA256SUMS ! -name '.sums.tmp' ! -name '.run-all.lock' -print0 | LC_ALL=C sort -z | xargs -0 -r sha256sum > .sums.tmp
mv .sums.tmp SHA256SUMS
sha256sum --quiet -c SHA256SUMS
du -sb .; du -sh .
wc -l SHA256SUMS
cd ..
archive=/root/20261125T130226Z-13d592774b63.tar.gz
test ! -e "$archive"
tar -cf - "$(basename "$b")" | gzip -1 > "$archive"
sha256sum "$archive"
stat -c '%s bytes' "$archive"
