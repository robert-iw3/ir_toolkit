#!/usr/bin/env bash
# ==============================================================================
# launch.sh - portable launcher for the containerized Binary Ninja used to RE
# memory regions carved out of true-positive YARA hits (tools/binja/data/).
#
# Figures out, dynamically, the things that differ across Linux distros / sessions:
#   • container runtime          podman (preferred) or docker
#   • X11 vs Wayland session     always render via XWayland/X11 (Qt xcb) - works on both
#   • X authorization            exports a wildcard X cookie the container user can read
#                                (Wayland's mutter Xwayland cookie is mode-600/uid-locked),
#                                plus a best-effort `xhost +local:`
#   • SELinux vs not             adds the :Z mount relabel only when SELinux is enforcing
#   • image present / missing    builds it (downloads Binary Ninja free) if needed
#   • Binary Ninja won't run as root -> the image already runs as the unprivileged binja user
#
# USAGE
#   ./launch.sh                         # mount tools/binja/data, open the BN GUI
#   ./launch.sh <carved.bin>            # open this carved region on launch (its dir is mounted)
#   ./launch.sh --data <DIR>            # mount DIR as /binja/data
#   ./launch.sh --build                 # force a rebuild first
#   ./launch.sh --shell                 # drop into a container shell (debug the mount/X)
#   ./launch.sh --stop                  # stop + remove the running container
# ==============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE="irtoolkit-binja"
NAME="irbinja"
DOCKERFILE="${HERE}/binja.Dockerfile"
DATA_DIR="${HERE}/data"
OPEN_FILE=""
FORCE_BUILD=0
MODE="gui"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --data)  DATA_DIR="$(cd "$2" && pwd)"; shift 2 ;;
        --build) FORCE_BUILD=1; shift ;;
        --shell) MODE="shell"; shift ;;
        --stop)  MODE="stop"; shift ;;
        -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *)  # a path: a carved file to open (mount its parent as data) or a data dir
            if [[ -f "$1" ]]; then
                DATA_DIR="$(cd "$(dirname "$1")" && pwd)"; OPEN_FILE="$(basename "$1")"
            elif [[ -d "$1" ]]; then
                DATA_DIR="$(cd "$1" && pwd)"
            else
                echo "not a file or directory: $1" >&2; exit 2
            fi
            shift ;;
    esac
done

# -- container runtime ---------------------------------------------------------
RUNTIME="$(command -v podman || command -v docker || true)"
[[ -z "$RUNTIME" ]] && { echo "ERROR: neither podman nor docker found." >&2; exit 1; }
RUNTIME="$(basename "$RUNTIME")"

if [[ "$MODE" == "stop" ]]; then
    "$RUNTIME" rm -f "$NAME" 2>/dev/null && echo "stopped $NAME" || echo "no $NAME running"
    exit 0
fi

# -- build the image if missing (or forced) — portable across podman/docker ----
have_image() { "$RUNTIME" image inspect "$IMAGE" >/dev/null 2>&1; }
if [[ "$FORCE_BUILD" -eq 1 ]] || ! have_image; then
    echo "[*] Building $IMAGE (downloads Binary Ninja free; needs internet)…"
    "$RUNTIME" build -t "$IMAGE" -f "$DOCKERFILE" "$HERE" || { echo "build failed" >&2; exit 1; }
fi

mkdir -p "$DATA_DIR"

# -- SELinux-aware mount suffix ------------------------------------------------
ZSUF=""
if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled 2>/dev/null; then ZSUF=":Z"; fi

# -- find the X display dynamically (any distro / session) ---------------------
# Prefer $DISPLAY; otherwise derive it from the first live /tmp/.X11-unix/X<N> socket
# (covers cases where the script runs without $DISPLAY exported, e.g. via sudo).
DISP="${DISPLAY:-}"
if [[ -z "$DISP" ]]; then
    for s in /tmp/.X11-unix/X*; do [[ -S "$s" ]] && { DISP=":${s##*/X}"; break; }; done
fi
DISP="${DISP:-:0}"

# -- find an X cookie the container user can use (X11 + Wayland/XWayland) -------
# $XAUTHORITY if usable, else the common per-distro locations (GNOME/mutter Xwayland,
# ~/.Xauthority, gdm). The cookie is rewritten to FamilyWild + made world-readable.
RUID="$(id -u)"
SRC_XAUTH="${XAUTHORITY:-}"
if [[ -z "$SRC_XAUTH" || ! -r "$SRC_XAUTH" ]]; then
    SRC_XAUTH=""
    for c in "$HOME/.Xauthority" \
             "${XDG_RUNTIME_DIR:-/run/user/$RUID}"/.mutter-Xwaylandauth.* \
             /run/user/"$RUID"/.mutter-Xwaylandauth.* \
             /run/user/"$RUID"/gdm/Xauthority; do
        [[ -r "$c" ]] && { SRC_XAUTH="$c"; break; }
    done
fi
XAUTH="$(mktemp /tmp/binja.xauth.XXXXXX)"
if command -v xauth >/dev/null 2>&1 && [[ -n "$SRC_XAUTH" && -r "$SRC_XAUTH" ]]; then
    # rewrite the family to FFFF (FamilyWild) so the cookie matches inside the container,
    # and make it world-readable so the unprivileged binja user can use it.
    xauth -f "$SRC_XAUTH" nlist "$DISP" 2>/dev/null | sed -e 's/^..../ffff/' | \
        xauth -f "$XAUTH" nmerge - 2>/dev/null || true
fi
chmod 644 "$XAUTH" 2>/dev/null || true
command -v xhost >/dev/null 2>&1 && xhost +local: >/dev/null 2>&1 || true   # belt-and-suspenders

if [[ ! -e /tmp/.X11-unix ]]; then
    echo "WARNING: /tmp/.X11-unix not found - no X server? On a headless box, run with --shell." >&2
fi

# -- run -----------------------------------------------------------------------
"$RUNTIME" rm -f "$NAME" >/dev/null 2>&1 || true
RUN_ARGS=(
    -d --name "$NAME" --net=host
    -v /tmp/.X11-unix:/tmp/.X11-unix
    -v "${XAUTH}:/tmp/binja.xauth:ro"
    -v "${DATA_DIR}:/binja/data${ZSUF}"
    -e "DISPLAY=${DISP}" -e XAUTHORITY=/tmp/binja.xauth
    -e LANG=C.UTF-8 -e LC_ALL=C.UTF-8
)
# podman: relax the X socket label so the container can reach it (no-op on docker)
[[ "$RUNTIME" == "podman" ]] && RUN_ARGS+=(--security-opt label=type:container_runtime_t)

if [[ "$MODE" == "shell" ]]; then
    echo "[*] Shell in $IMAGE (data at /binja/data). 'exit' to leave."
    "$RUNTIME" run --rm -it "${RUN_ARGS[@]:1}" --entrypoint /bin/bash "$IMAGE"
    rm -f "$XAUTH"; exit 0
fi

CMD=(./binaryninja)
if [[ -n "$OPEN_FILE" ]]; then
    CMD+=("/binja/data/${OPEN_FILE}")
else
    # default: OPEN EVERY carved region in the data tree (BN opens one tab per file), so the
    # analyst lands straight on the bins to analyze rather than an empty start screen.
    nbins=0
    while IFS= read -r f; do
        CMD+=("/binja/data/${f#"${DATA_DIR}/"}")
        nbins=$((nbins + 1))
    done < <(find "$DATA_DIR" -type f -name '*.bin' | sort)
    [[ $nbins -eq 0 ]] && echo "[*] No carved .bin in $DATA_DIR yet — opening the BN start screen." >&2
fi
"$RUNTIME" run "${RUN_ARGS[@]}" "$IMAGE" "${CMD[@]}" >/dev/null

sleep 4
if "$RUNTIME" ps --filter "name=${NAME}" --format '{{.Names}}' | grep -q "$NAME"; then
    echo "[+] Binary Ninja launched (runtime=$RUNTIME). Data mounted from: $DATA_DIR"
    [[ -n "$OPEN_FILE" ]] && echo "    opening: $OPEN_FILE"
    echo "    logs: $RUNTIME logs -f $NAME   |   stop: $0 --stop"
else
    echo "[!] Container exited - last logs:" >&2
    "$RUNTIME" logs "$NAME" 2>&1 | tail -8 >&2
    echo "    (try: $0 --shell   to debug the mount/X setup)" >&2
fi
