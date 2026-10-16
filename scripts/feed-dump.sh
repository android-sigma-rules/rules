# Feed dump format (read by validation/check-reference.py):
#   "## <path>"  header line, one per upstream file
#   "| <line>"   every content line of that file
# awk always terminates the last line (sed does not, which glued the next header onto it — plan gate
# round 6, R6-1) and turns every \r into a space (a bare \r is a line break to Python — S6-1).
# Files whose names contain a newline or \r are skipped; .git/ is excluded.
cap() { head -c 200000000; }   # 200 MB per dump
dump() {
  (cd "$1" && find . -path ./.git -prune -o -type f \( "${@:2}" \) -print0 | sort -z |
   while IFS= read -r -d '' f; do
     case "$f" in *$'\n'*|*$'\r'*) continue ;; esac
     printf '## %s\n' "${f#./}"
     awk '{ gsub(/\r/, " "); print "| " $0 }' "$f"
   done) | cap
}
