#!/usr/bin/env bash
# Load and unload the promote deploy key for the jobs of the promote workflow.
#
# A script is needed because no action or tool does this with the properties we
# need: the key goes from the environment secret into an ssh-agent through
# stdin and never touches a file, the agent socket is private to the job, and
# ssh checks the server against GitHub's published host key and nothing else.
# The steps would otherwise repeat these lines in two jobs.
#
#   PROMOTE_DEPLOY_KEY=... ci/promote-key.sh load     # needs GITHUB_ENV and RUNNER_TEMP
#   ci/promote-key.sh unload
#
# `load` exports SSH_AUTH_SOCK, SSH_AGENT_PID and GIT_SSH_COMMAND to the later
# steps of the job through GITHUB_ENV. Only the step that runs `load` receives
# the secret. This script must run only in a job without candidate code.
set -euo pipefail

# From https://api.github.com/meta (ssh_keys). This is a public value. If
# GitHub rotates its key, the push fails closed until this line is updated.
github_host_key='github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'

dir="${RUNNER_TEMP:?RUNNER_TEMP is not set}/promote-ssh"

case "${1:-}" in
  load)
    : "${PROMOTE_DEPLOY_KEY:?PROMOTE_DEPLOY_KEY is not set}"
    : "${GITHUB_ENV:?GITHUB_ENV is not set}"
    rm -rf "$dir"
    mkdir -m 700 "$dir"
    printf '%s\n' "$github_host_key" > "$dir/known_hosts"
    sock="$dir/agent.sock"
    out="$(ssh-agent -a "$sock" -s)"
    pid="$(sed -n 's/^echo Agent pid \([0-9]*\);$/\1/p' <<< "$out")"
    [ -n "$pid" ] || { echo "promote-key: ssh-agent did not report a pid" >&2; exit 1; }
    printf '%s\n' "$PROMOTE_DEPLOY_KEY" | tr -d '\r' | SSH_AUTH_SOCK="$sock" ssh-add - >/dev/null
    {
      echo "SSH_AUTH_SOCK=$sock"
      echo "SSH_AGENT_PID=$pid"
      echo "GIT_SSH_COMMAND=ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$dir/known_hosts -o GlobalKnownHostsFile=/dev/null -o HostKeyAlgorithms=ssh-ed25519 -o PasswordAuthentication=no"
    } >> "$GITHUB_ENV"
    echo "promote-key: key loaded into a private agent"
    ;;
  unload)
    if [ -S "$dir/agent.sock" ]; then
      SSH_AUTH_SOCK="$dir/agent.sock" ssh-add -D >/dev/null 2>&1 || true
      if [ -n "${SSH_AGENT_PID:-}" ]; then kill "$SSH_AGENT_PID" 2>/dev/null || true; fi
    fi
    rm -rf "$dir"
    echo "promote-key: key removed"
    ;;
  *)
    echo "usage: promote-key.sh load|unload" >&2
    exit 2
    ;;
esac
