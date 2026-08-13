#!/usr/bin/env bash
# Interceptor. Proxy on :8080, UI on :9000 (loopback only).
#
# Safe to symlink onto your PATH -- it resolves back to the real project dir:
#   ln -s "$PWD/run.sh" /usr/local/bin/interceptor
#
# Env overrides, so a test run can never collide with an instance you have up:
#   IC_LISTEN_HOST  IC_LISTEN_PORT  IC_UI_PORT  IC_URL_FILE  IC_OPEN_UI
set -euo pipefail

# Follow the symlink chain to find the project, not the symlink's directory.
SELF="${BASH_SOURCE[0]}"
while [ -L "$SELF" ]; do
  LINK="$(readlink "$SELF")"
  case "$LINK" in
    /*) SELF="$LINK" ;;
    *)  SELF="$(dirname "$SELF")/$LINK" ;;
  esac
done
cd "$(cd "$(dirname "$SELF")" && pwd -P)"

if [ ! -x .venv/bin/mitmdump ]; then
  echo "No .venv here. Set it up once:" >&2
  echo "  uv venv --python 3.13 .venv && uv pip install --python .venv/bin/python -r requirements.txt" >&2
  exit 1
fi

# --- loopback guard -----------------------------------------------------------
# This has to live here, not in the addon. mitmproxy brings the proxy listener up
# BEFORE any script addon loads -- verified: with an unbindable host, "HTTP(S)
# proxy failed to listen" is logged one line ABOVE "Loading script". So by the
# time the addon could object, the socket is already public. Refusing to exec is
# the only point that actually prevents it. The addon keeps its own copy of this
# check for `mitmdump -s` used directly, but it cannot be the primary.
is_loopback() {
  case "$1" in 127.*|::1|localhost|localhost.) return 0 ;; *) return 1 ;; esac
}

# A mode spec can carry its own bind address, and proxyserver prefers it over
# listen_host: `--mode regular@0.0.0.0:8080` is an open proxy with listen_host
# still reading 127.0.0.1. Print the host half, or nothing when there is none
# (`regular`, `regular@8080`, `upstream:http://vps:8080` -- that @ belongs to the
# upstream URL's userinfo/host, not to a bind address, and parses as no host).
mode_bind_host() {
  local tail="$1"
  case "$tail" in *@*) tail="${tail##*@}" ;; *) return 0 ;; esac
  case "$tail" in
    ''|*[!0-9]*) ;;    # has a host part
    *) return 0 ;;     # bare port, e.g. regular@8080
  esac
  case "$tail" in
    \[*\]*) tail="${tail%%]*}"; tail="${tail#[}" ;;   # [::]:8080
    *:*)    tail="${tail%:*}" ;;                      # host:port
  esac
  printf '%s' "$tail"
}

check_mode() {
  local host
  host="$(mode_bind_host "$1")"
  if [ -n "$host" ]; then
    is_loopback "$host" || BAD="$BAD --mode $1"
  fi
}

# `-m` is a documented alias for --mode ("--mode, -m MODE"), and short flags
# cluster: `-qm spec` is -q plus -m spec, `-qmspec` attaches the value. Both got
# past an earlier version of this guard, and both reached the bind -- verified
# against an unbindable address, with the addon's refusal arriving only after
# "failed to listen". So walk the cluster rather than matching one spelling.
# The first value-taking flag swallows the remainder, so stop at it: in `-pm 8080`
# the m belongs to -p's value, not to a mode.
scan_short_cluster() {
  local rest="$1" c
  while [ -n "$rest" ]; do
    c="${rest%"${rest#?}"}"
    rest="${rest#?}"
    case "$c" in
      m) if [ -n "$rest" ]; then check_mode "$rest"; else WANT=mode; fi; return 0 ;;
      p|s|r|w|M|B|H|C|S) return 0 ;;   # takes a value; the rest is that value
      *) ;;                            # boolean flag: keep walking the cluster
    esac
  done
}

# --- upstream proxy chaining (opt-in: --chain) -----------------------------------
# On a machine whose egress goes through a proxy client (Clash, Surge, a corporate
# proxy), dialling out directly fails with a bare "502 Bad Gateway / connection
# closed". `--chain` puts the configured proxy upstream so those requests work.
#
# Opt-in, NOT the default, and that is deliberate. Detection cannot be trusted to be
# right everywhere: `scutil` is macOS-only, so Linux and WSL fall back to environment
# variables, and a VPN that installs a route or a TUN interface rather than a proxy
# setting is invisible to both. Defaulting to "chain if we think we found something"
# means the tool routes traffic differently depending on the OS and the client, and
# silently goes direct on the setups it cannot see. One flag that always means the
# same thing beats a guess that is right most of the time.
#
# Detection still runs unconditionally, but only to inform: IC_DETECTED_PROXY is
# exported so the UI can explain a 502 rather than leaving it a mystery.
#
# scutil is asked first, and the environment only as a fallback: a shell that was
# open when the proxy got toggled still carries the old HTTPS_PROXY, so the env is
# the less trustworthy of the two.
detect_proxy() {
  if command -v scutil >/dev/null 2>&1; then
    local out host port on
    out="$(scutil --proxy 2>/dev/null || true)"
    on="$(printf '%s\n' "$out"  | awk '/HTTPSEnable/ {print $3; exit}')"
    host="$(printf '%s\n' "$out" | awk '/HTTPSProxy/ {print $3; exit}')"
    port="$(printf '%s\n' "$out" | awk '/HTTPSPort/ {print $3; exit}')"
    if [ "${on:-0}" = "1" ] && [ -n "${host:-}" ] && [ -n "${port:-}" ]; then
      printf 'http://%s:%s' "$host" "$port"
      return 0
    fi
  fi
  for v in "${HTTPS_PROXY:-}" "${https_proxy:-}" "${HTTP_PROXY:-}" "${http_proxy:-}"; do
    if [ -n "$v" ]; then printf '%s' "$v"; return 0; fi
  done
}

# "http://user@127.0.0.1:7897/" -> "127.0.0.1 7897"
proxy_hostport() {
  local u="${1#*://}"
  u="${u%%/*}"
  u="${u##*@}"
  local h="${u%:*}" p="${u##*:}"
  if [ "$h" = "$p" ]; then p=80; fi
  printf '%s %s' "$h" "$p"
}

# Would chaining to this proxy point us at ourselves? People do set a system proxy
# to this tool to capture everything on the machine, and adopting that as upstream
# is an immediate loop.
is_self() {
  local h p lh lp
  read -r h p <<EOF
$(proxy_hostport "$1")
EOF
  lh="${IC_LISTEN_HOST:-127.0.0.1}"
  lp="${IC_LISTEN_PORT:-8080}"
  case "$h" in 127.*|localhost|localhost.|::1) h=loopback ;; esac
  case "$lh" in 127.*|localhost|localhost.|::1) lh=loopback ;; esac
  [ "$h" = "$lh" ] && [ "$p" = "$lp" ]
}

# Only loopback proxies are probed: that is where "the client is switched off but the
# setting stayed" happens, and a connect to loopback answers instantly either way.
# A remote proxy was configured deliberately and might blackhole a probe, so it is
# taken at its word rather than risking a hang at startup.
proxy_reachable() {
  local h p
  read -r h p <<EOF
$(proxy_hostport "$1")
EOF
  case "$h" in
    127.*|localhost|localhost.|::1) (exec 3<>"/dev/tcp/$h/$p") >/dev/null 2>&1 ;;
    *) return 0 ;;
  esac
}

ARGS=()
CHAIN=""
for arg in "$@"; do
  if [ "$arg" = "--chain" ]; then CHAIN=1; else ARGS+=("$arg"); fi
done

# Always detected, never acted on without --chain. The UI reads this to explain a
# 502; the startup line below is no help to someone who launched Chrome from the UI
# and never looks at this terminal.
DETECTED="$(detect_proxy)"
export IC_DETECTED_PROXY="$DETECTED"

if [ -n "$CHAIN" ]; then
  if [ -z "$DETECTED" ]; then
    echo "interceptor: --chain found no proxy configured; connecting directly." >&2
    echo "             Detection is scutil (macOS) then HTTP(S)_PROXY -- a VPN that" >&2
    echo "             installs a route rather than a proxy will not show up. Pass" >&2
    echo "             --mode upstream:http://host:port to name one yourself." >&2
  elif is_self "$DETECTED"; then
    # A system proxy aimed at this listener would make us our own upstream.
    echo "interceptor: refusing to chain -- $DETECTED is this proxy, which would be" >&2
    echo "             an infinite loop. Point the system proxy elsewhere." >&2
  elif ! proxy_reachable "$DETECTED"; then
    echo "interceptor: $DETECTED is configured but not answering (client switched" >&2
    echo "             off?), so connecting directly." >&2
  else
    echo "interceptor: chaining upstream to $DETECTED (--chain)" >&2
    ARGS+=(--mode "upstream:$DETECTED")
  fi
fi
set -- ${ARGS[@]+"${ARGS[@]}"}

EXPOSE=false
BAD=""
WANT=""   # what the NEXT argument is a value for
for arg in "$@"; do
  case "$WANT" in
    mode)        WANT=""; check_mode "$arg"; continue ;;
    listen_host) WANT=""; is_loopback "$arg" || BAD="$BAD --listen-host $arg"; continue ;;
  esac
  case "$arg" in
    expose=true)                 EXPOSE=true ;;
    listen_host=*|ui_host=*)     is_loopback "${arg#*=}" || BAD="$BAD $arg" ;;
    --listen-host=*)             is_loopback "${arg#*=}" || BAD="$BAD $arg" ;;
    --listen-host)               WANT=listen_host ;;
    mode=*|--mode=*)             check_mode "${arg#*=}" ;;
    --mode)                      WANT=mode ;;
    --*)                         ;;  # any other long option
    -?*)                         scan_short_cluster "${arg#-}" ;;
  esac
done
is_loopback "${IC_LISTEN_HOST:-127.0.0.1}" || BAD="$BAD IC_LISTEN_HOST=${IC_LISTEN_HOST}"

if [ -n "$BAD" ] && [ "$EXPOSE" != true ]; then
  cat >&2 <<EOF
interceptor: refusing to bind off loopback:$BAD

  The proxy port has no authentication of any kind. Off loopback, that is an open
  MITM proxy: anyone who can reach the port can route their traffic through you,
  read it decrypted, and have it rewritten.

  If that is genuinely what you want, say so explicitly and firewall the port:
    $(basename "$0")$BAD --set expose=true
EOF
  exit 2
fi

# ssl_insecure: uncomment to accept self-signed/expired certs on staging targets.
#   --set ssl_insecure=true
exec .venv/bin/mitmdump \
  -s addon/interceptor.py \
  --set listen_host="${IC_LISTEN_HOST:-127.0.0.1}" \
  --set listen_port="${IC_LISTEN_PORT:-8080}" \
  --set ui_port="${IC_UI_PORT:-9000}" \
  --set url_file="${IC_URL_FILE:-.ui-url}" \
  --set open_ui="${IC_OPEN_UI:-true}" \
  --set flow_detail=0 \
  "$@"
