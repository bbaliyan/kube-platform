set -eu

prom="/host$TEXTFILE_DIR/os_updates.prom"
dir="$(dirname "$prom")"
mkdir -p "$dir"

# On an SELinux host, node-exporter runs confined and can read only
# container_ro_file_t here, not the default var_lib_t. A failure or a host
# without SELinux must not stop the loop.
label_for_node_exporter() {
  chroot /host sh -c '
    command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled || exit 0
    chcon -R -t container_ro_file_t "$1"
  ' sh "${dir#/host}" || echo "could not label ${dir#/host} for node-exporter" >&2
}

collect() {
  os=$(. /host/etc/os-release && echo " $ID ${ID_LIKE:-} ")
  case "$os" in
    *" debian "*) chroot /host /bin/sh -s < /scripts/apt.sh ;;
    *" rhel "* | *" fedora "*) chroot /host /bin/bash -s < /scripts/yum.sh ;;
    *) echo "unsupported OS:$os" >&2; return 1 ;;
  esac
}

while true; do
  label_for_node_exporter
  if collect > "$prom.tmp"; then
    mv "$prom.tmp" "$prom"
    label_for_node_exporter
  else
    rm -f "$prom.tmp"
  fi
  sleep "$INTERVAL_SECONDS"
done
