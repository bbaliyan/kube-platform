set -eu

upgrades=$(apt-get --simulate -o Debug::NoLocking=1 dist-upgrade)

echo '# HELP apt_upgrades_pending Apt packages pending updates by origin.'
echo '# TYPE apt_upgrades_pending gauge'
printf '%s\n' "$upgrades" | awk '
  /^Inst / {
    s = $0
    sub(/\)( \[[^]]*\])*$/, ")", s)
    sub(/^[^(]*\(/, "", s)
    arch = s
    sub(/.*\[/, "", arch)
    sub(/\].*/, "", arch)
    sub(/ \[[^]]*\]\)$/, "", s)
    sub(/^[^ ]+ /, "", s)
    gsub(/, /, ",", s)
    if (!((s, arch) in pending)) n++
    pending[s, arch]++
  }
  END {
    for (k in pending) {
      split(k, f, SUBSEP)
      printf "apt_upgrades_pending{origin=\"%s\",arch=\"%s\"} %d\n", f[1], f[2], pending[k]
    }
    if (n == 0) print "apt_upgrades_pending{origin=\"\",arch=\"\"} 0"
  }'

echo '# HELP node_reboot_required Node reboot is required for software updates.'
echo '# TYPE node_reboot_required gauge'
if [ -f /run/reboot-required ]; then
  echo 'node_reboot_required 1'
else
  echo 'node_reboot_required 0'
fi

stamp=/var/lib/apt/periodic/update-success-stamp
if [ -f "$stamp" ]; then
  echo '# HELP apt_package_cache_timestamp_seconds Apt update last run time.'
  echo '# TYPE apt_package_cache_timestamp_seconds gauge'
  echo "apt_package_cache_timestamp_seconds $(stat -c %Y "$stamp")"
fi
