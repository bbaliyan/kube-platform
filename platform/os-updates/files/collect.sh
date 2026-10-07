set -eu

prom="/host$TEXTFILE_DIR/os_updates.prom"
mkdir -p "$(dirname "$prom")"

collect() {
  os=$(. /host/etc/os-release && echo " $ID ${ID_LIKE:-} ")
  case "$os" in
    *" debian "*) chroot /host /bin/sh -s < /scripts/apt.sh ;;
    *" rhel "* | *" fedora "*) chroot /host /bin/bash -s < /scripts/yum.sh ;;
    *) echo "unsupported OS:$os" >&2; return 1 ;;
  esac
}

while true; do
  if collect > "$prom.tmp"; then
    mv "$prom.tmp" "$prom"
  else
    rm -f "$prom.tmp"
  fi
  sleep "$INTERVAL_SECONDS"
done
