#!/usr/bin/env bash
#
# nfoslide.sh - terminal slideshow of random NFO and ANSI art from 16colo.rs
#
# Nothing is ever written to disk. All content lives in shell variables and
# pipes. Remote bytes are treated as hostile: they are interpreted onto a
# bounded off-screen canvas rather than sent to the terminal (see AWK_ANSI and
# THREAT MODEL below).
#
#   ./nfoslide.sh             run the slideshow
#   ./nfoslide.sh --selftest  check your font, glyph widths and colour depth
#   ./nfoslide.sh --dump P/F  one file's bytes and metadata, for reporting bugs
#   ./nfoslide.sh --probe     check each API hop and show a sample, then exit
#   ./nfoslide.sh --diagnose  full headers/bodies, for diagnosing a 403
#   ./nfoslide.sh --help      options and keys
#
# ---------------------------------------------------------------------------
# THREAT MODEL (short version, because it matters here)
#
# Adversary: whoever controls the bytes we render. Realistically that is an
# archive of decades-old files uploaded by strangers, plus anyone who can MITM
# or spoof the fetch. Their goal is to get a control sequence onto your tty.
#
# Writing untrusted bytes straight to a terminal is a real, exploited bug class,
# not a theoretical one:
#
#   * OSC 52 writes to the system clipboard. Attacker stages "rm -rf ~" and
#     waits for your next paste.
#   * Window-title set (OSC 0/2) followed by title-report (CSI 21t) makes the
#     terminal echo the attacker's string back on *stdin* - i.e. as if you
#     typed it. On many terminals that is command execution at your next
#     Enter keypress.
#   * DCS/APC/PM payloads, DECRQSS replies, and charset switches can wedge or
#     re-map the terminal.
#   * Cursor addressing (CUP/ED) lets content overwrite the header and lie
#     about which file you are looking at.
#
# Control: the file is never sent to the terminal. It is INTERPRETED onto a
# bounded off-screen grid (AWK_ANSI), and only the finished grid is printed.
#
#   - Cursor motion is executed against that grid and clamped to it, so
#     hostile positioning can overwrite the picture and nothing else. It
#     cannot reach the header, the status line or the shell prompt. This is
#     both safer and more faithful than dropping those sequences, which is
#     what an earlier version did at the cost of destroying the art.
#   - OSC, DCS, SOS, PM, APC and charset designators are consumed and
#     discarded outright: they address the terminal, not the canvas.
#   - The OUTPUT contains only SGR. Nothing else can reach the tty, whatever
#     the input was.
#   - MAXROWS/MAXCOLS bound the grid, so ESC[999999B is not an allocation bomb.
#
# Charset conversion runs BEFORE the canvas, and the canvas consumes a UTF-8
# lead byte together with its continuations. A cell is therefore never split
# and a continuation byte can never be read as an escape introducer. Nothing
# downstream re-interprets the bytes, so there is no second pass to fool.
#
# Transport: HTTPS pinned to one host, redirects capped and forced to stay
# HTTPS on that host, response size capped. No --insecure, ever. Pack and file
# names parsed out of remote JSON are re-validated against a strict charset
# before being interpolated into a URL, so a malicious API response cannot
# walk us into path traversal or SSRF. Artist and group names go through a
# separate allowlist before reaching the header, and the header truncates the
# metadata rather than the key hints.
#
# Residual risk accepted: terminals with non-standard extensions may honour
# something inside an SGR parameter list. Params are constrained to [0-9;] to
# shrink that surface. If you do not care about colour at all, run with
# --no-colour for a strictly-text render.
# ---------------------------------------------------------------------------

set -Eeuo pipefail
IFS=$'\n\t'

# --- preconditions ---------------------------------------------------------

if (( BASH_VERSINFO[0] < 4 )); then
  printf 'nfoslide: needs bash 4.0+ (found %s). On macOS: brew install bash\n' \
    "${BASH_VERSION}" >&2
  exit 1
fi

for _dep in curl awk sed; do
  command -v "$_dep" >/dev/null 2>&1 || {
    printf 'nfoslide: missing required tool: %s\n' "$_dep" >&2; exit 1; }
done
if command -v iconv >/dev/null 2>&1; then HAVE_ICONV=1; else HAVE_ICONV=0; fi

# --- configuration ---------------------------------------------------------
# Every network-facing constant is here so the trust boundary is auditable in
# one place. Overridable by env var, but never by remote content.

# 16colo.rs, the ANSI/ASCII artpack archive. Defacto2 was the original target
# but sits behind a Cloudflare managed challenge (cf-mitigated: challenge) on
# every path including the SQL dump it advertises for programmatic use. That
# is an access control the operator chose; it is not something to defeat.
# Point NFO_HOST back at defacto2.net if they ever whitelist their own API.
#
# API lives on a SEPARATE subdomain: api.16colo.rs, not 16colo.rs/api.
readonly HOST="${NFO_HOST:-16colo.rs}"          # content host
readonly BASE="https://${HOST}"
readonly API_URL="${NFO_API:-https://api.${HOST}/v1}"
readonly YEAR_MIN="${NFO_YEAR_MIN:-1990}"
readonly FILES_PER_PACK="${NFO_FILES_PER_PACK:-3}"

# Extensions worth rendering as text. Everything else in a pack (EXE, DAT,
# ZIP, PNG, module music) is skipped rather than sprayed at the terminal.
readonly TEXT_EXT_RE='[.](nfo|ans|asc|txt|diz)$'

# Widest canvas we will build, in characters. 132- and 160-column art is
# common; beyond this a file is almost certainly not art. Shared by the shell
# (bounding widths that arrive from the API) and the awk renderer (bounding
# how much memory a crafted file can make us allocate), so there is one number
# to change rather than two that can drift apart.
readonly ART_MAX_COLS="${NFO_MAX_COLS:-320}"
readonly ART_MAX_ROWS="${NFO_MAX_ROWS:-1000}"

# Column at which content is soft-wrapped. ANSI art is authored for 80; the
# terminal cannot be relied on to wrap because autowrap is disabled during
# rendering (see term_init).

# An honest, contactable identifier is correct crawler etiquette: it is what
# the site operators would want to see in their logs when deciding whether to
# allow this client. Override with NFO_UA (put your email in it if you run this
# a lot). Deliberately NOT a spoofed browser string.
readonly UA="${NFO_UA:-nfoslide/1.2 (terminal NFO viewer; rate-limited; +set NFO_UA to identify yourself)}"
readonly MAX_BYTES="${NFO_MAX_BYTES:-2000000}"   # 2 MB cap; NFOs are ~2-50 KB
readonly MAX_BYTES_INDEX="${NFO_MAX_INDEX:-33554432}"  # 32 MB; year listings are big
readonly CONNECT_TIMEOUT=6
readonly MAX_TIME=20                            # bounds the longest silent gap
readonly MAX_REDIRS=3
readonly RETRIES=3
readonly DISCOVERY_RETRIES=2                    # fail fast, before the alt screen
readonly MIN_REQUEST_GAP=1                      # be a decent guest on a
                                                # volunteer-run archive

SHORT_MIN="${NFO_SHORT_MIN:-10}"                 # seconds, short NFO
SHORT_MAX="${NFO_SHORT_MAX:-15}"
SCROLL_DELAY="${NFO_SCROLL_DELAY:-1.2}"          # seconds per line, spec says 1-2
MAX_SLIDE_SECONDS="${NFO_MAX_SLIDE:-180}"
END_HOLD="${NFO_END_HOLD:-4}"                   # linger at end of a scroll
SCROLL_GRACE="${NFO_SCROLL_GRACE:-6}"           # auto-scroll pause after a
                                                # manual scroll, in seconds
HIST_MAX="${NFO_HISTORY:-50}"                   # artworks kept for back/forward
SEEN_MAX="${NFO_SEEN_MAX:-5000}"                # de-dup memory before it resets
HIST_BUDGET="${NFO_HISTORY_BYTES:-16777216}"    # 16 MB ceiling on that cache
readonly PAUSE_WAIT=3600                        # how long a paused slide waits        # hard cap; long files speed up
SMOOTH=1                                        # wipe transition
CENTRE=1                                        # centre the art on screen
ICE_COLOURS=1                                   # SGR 5 = bright background
HYBRID_WRAP=1                                   # see the wrap note in AWK_ANSI

# Draw with the real CGA/VGA palette as 24-bit colour rather than the
# terminal's own sixteen. Default on where the terminal advertises truecolor:
# emitting 24-bit SGR at a terminal that cannot do it looks worse than the
# theme mismatch it fixes, so this is opt-out there and opt-in elsewhere.
case "${NFO_PALETTE:-${COLORTERM:-}}" in
  vga)                VGA_PALETTE=1 ;;
  term|terminal)      VGA_PALETTE=0 ;;
  truecolor|24bit)    VGA_PALETTE=1 ;;
  *)                  VGA_PALETTE=0 ;;
esac
KEEPCOLOUR=1
PROBE=0
DIAGNOSE=0
DUMP_SPEC=""
DUMP_AT=""
SELFTEST=0
NFO_ANSI_WIDTH="${NFO_ANSI_WIDTH:-0}"

# --- state -----------------------------------------------------------------

declare -a PACKS=()        # pack names for the current year
declare -a FILES=()        # renderable files in the current pack
YEAR=""                    # year the current pool came from
NFO_WIDTH=0                # widest visible line of the current file
CUR_RAW=""                 # raw bytes of the current artwork, kept so the
CUR_W=0                    # canvas width can be changed without refetching
CUR_ICE=$ICE_COLOURS       # iCE colours for the current file (SAUCE may say)
REWIDTH_KEEP=0             # preserve the scroll offset across a re-render
PICKED=""                  # result of pick_into (see why it is not a subshell)
CUR_META=""                # artist / group line for the header
declare -A SEEN=()         # "pack/file" already shown, so we do not repeat
declare -A YEAR_CACHE=()   # year -> newline-joined pack names
declare -A PACK_GROUP=()   # pack -> group names
declare -A FILE_ARTIST=()  # file -> artist names (current pack only)
declare -A FILE_COLS=()    # file -> character width derived from the API
declare -A FILE_PX=()      # file -> the raw pixel width it was derived from
declare -A FILE_ICE=()     # file -> "true"/"false" if SAUCE states it
declare -A FILE_SAUCE_H=() # file -> row count SAUCE claims, for cross-checking
PAUSED=0                   # space toggles; survives across slides
HIST_LABEL=""              # "history 3/12" marker for the status line
declare -a HIST_KEY=() HIST_TEXT=() HIST_META=() HIST_W=() HIST_RAW=() HIST_CW=()
HIST_POS=-1                # index currently on screen; last element = live
HIST_BYTES=0               # running size of HIST_TEXT, so a long session
                           # cannot grow without bound
declare -a NFO_LINES=()    # current file, one line per element
ROWS=24; COLS=80
LAST_REQUEST=0
KEY_ACTION=""              # timeout | skip | quit
CLEANED=0
INTERACTIVE=0
TERM_READY=0
STTY_SAVE=""
SHOWN=0; SKIPPED=0; ERRORS=0
LAST_HTTP=""           # status code of the most recent request
FETCH_BODY=""          # body of the most recent request (see fetch)
PROGRESS=1             # print fetch progress (off once the alt screen is up)

# --- logging ---------------------------------------------------------------
# Deliberately terse and never interpolates remote text into a format string.

warn() { printf 'nfoslide: %s\n' "$*" >&2; }
die()  { warn "$*"; exit 1; }

usage() {
  cat <<'USAGE'
nfoslide.sh - random NFO / ANSI art slideshow from 16colo.rs

  --delay SECONDS     seconds per line while auto-scrolling (default 1.2)
  --short MIN,MAX     hold time for files that fit on screen (default 10,15)
  --max-slide SECONDS cap on any one slide; long files scroll faster to fit
  --width N           pin the canvas width (default: from the API per file)
  --no-center         left-align instead of centring
  --no-smooth         plain clear instead of the wipe transition
  --no-colour         strip ANSI colour as well as everything else
  --blink             read SGR 5 as blink rather than an iCE bright background
  --palette vga|term  draw with the real VGA colours, or the terminal's own
                      (default: vga when the terminal reports truecolor)
  --probe             check each API hop and show a sample, then exit
  --diagnose          full headers and error bodies, for a blocked/403 case
  --dump PACK/FILE    print one file's bytes and metadata, for reporting bugs
  --at ROW            with --dump: show a window around ROW, not the head
  --selftest          check your font, glyph widths and colour depth
  --help              this

Keys
  space               pause / resume (stays paused until you press it again)
  up / down           scroll one line
  PgUp / PgDn         scroll one screen
  Home / End          jump to start or end of the file
  left / right        previous / next artwork, from the in-memory history
  [ / ]               canvas width -1 / +1 columns, re-rendered live
  { / }               canvas width -8 / +8 columns
  w                   switch line-wrap reading (DOS-style vs strict VT100)
  p                   switch palette between the real VGA colours and yours
  q                   quit
  any other key       next file

  The canvas width comes from the archive metadata, falling back to 80 for
  art. If a piece looks sheared or sliced the width is wrong: nudge it with
  [ and ] until it lines up. The width in use is shown as "w80" in the status.

  Scrolling by hand suspends the auto-scroll for a few seconds so you can
  read; space holds it indefinitely. The last 50 artworks stay rendered in
  memory, so left/right is instant and costs no requests.

Source: 16colo.rs artpacks (.nfo .ans .asc .txt .diz), CP437, no disk writes.
A random year and pack is drawn for every few files, so a long session walks
the whole archive rather than one year.

Environment
  NFO_HOST NFO_API NFO_UA          where to fetch from, and how to identify
  NFO_YEAR_MIN NFO_FILES_PER_PACK  how widely to roam
  NFO_ANSI_WIDTH                   same as --width
  NFO_PALETTE                      vga or term; same as --palette
  NFO_MAX_COLS NFO_MAX_ROWS        canvas ceiling (320x1000)
  NFO_SCROLL_DELAY NFO_SHORT_MIN NFO_SHORT_MAX NFO_MAX_SLIDE NFO_END_HOLD
  NFO_SCROLL_GRACE                 manual-scroll pause, seconds (default 6)
  NFO_HISTORY NFO_HISTORY_BYTES    history depth and its memory ceiling
  NFO_MAX_BYTES NFO_MAX_INDEX      response size caps
USAGE
}

while (( $# )); do
  case $1 in
    --delay)      SCROLL_DELAY=${2:?}; shift 2 ;;
    --short)      SHORT_MIN=${2%%,*}; SHORT_MAX=${2##*,}; shift 2 ;;
    --max-slide)  MAX_SLIDE_SECONDS=${2:?}; shift 2 ;;
    --no-smooth)  SMOOTH=0; shift ;;
    --no-center|--no-centre) CENTRE=0; shift ;;
    --width)      NFO_ANSI_WIDTH=${2:?}; shift 2 ;;
    --no-colour|--no-color) KEEPCOLOUR=0; shift ;;
    --blink)      ICE_COLOURS=0; shift ;;
    --palette)    case ${2:?} in
                    vga)           VGA_PALETTE=1 ;;
                    term|terminal) VGA_PALETTE=0 ;;
                    *) die "--palette takes vga or term" ;;
                  esac; shift 2 ;;
    --probe)      PROBE=1; shift ;;
    --diagnose)   DIAGNOSE=1; shift ;;
    --dump)       DUMP_SPEC=${2:?}; shift 2 ;;
    --at)         DUMP_AT=${2:?}; shift 2 ;;
    --selftest)   SELFTEST=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *)            usage >&2; die "unknown option: $1" ;;
  esac
done

[[ $SCROLL_DELAY =~ ^[0-9]+([.][0-9]+)?$ ]] || die "--delay must be numeric"
[[ $SHORT_MIN =~ ^[0-9]+$ && $SHORT_MAX =~ ^[0-9]+$ ]] || die "--short must be MIN,MAX"

# ===========================================================================
# NETWORK
# ===========================================================================

# Reject anything that is not plain https on the pinned host. Parses the
# authority itself rather than trusting a substring match, so
# https://16colo.rs@evil.example/ and https://evil-16colo.rs/ both fail.
url_is_allowed() {
  local url=$1 authority host
  [[ $url == https://* ]] || return 1
  authority=${url#https://}
  authority=${authority%%/*}
  if [[ $authority == *@* ]]; then return 1; fi        # userinfo spoofing
  host=${authority%%:*}
  host=${host,,}
  [[ $host == "$HOST" || $host == *".$HOST" ]]
}

# Artifact ids are interpolated into URLs, so they get a strict allowlist.
# Pack names and filenames arrive inside a JSON body from the network and are
# then interpolated into a URL path. Strict allowlists, and an explicit ".."
# check on top, because a charset allowlist that happens to include "." still
# permits traversal.
pack_is_valid() {
  [[ $1 =~ ^[A-Za-z0-9._-]{1,64}$ ]] && [[ $1 != *..* ]] && [[ $1 == *[A-Za-z0-9]* ]]
}

# Sub-delims are legal in a path segment, so DOS-era names like NN!LOGO.ANS
# work unencoded. "#", "?", "%", "/" and "\\" are excluded: they would change
# how the URL parses rather than just naming a file.
# The final test requires at least one alphanumeric character. Without it a
# name of nothing but dots and dashes passes the charset check -- "." is not a
# traversal, but it is not a filename either, and building a URL out of one is
# never right.
file_is_valid() {
  [[ $1 =~ ^[A-Za-z0-9._!\$\&()+,\;=@~^-]{1,80}$ ]] && [[ $1 != *..* ]] \
    && [[ $1 == *[A-Za-z0-9]* ]]
}

throttle() {
  local now gap
  now=$(( $(date +%s) ))
  gap=$(( now - LAST_REQUEST ))
  if (( gap < MIN_REQUEST_GAP )); then sleep "$(( MIN_REQUEST_GAP - gap ))"; fi
  LAST_REQUEST=$(( $(date +%s) ))
}

# Fetch to stdout. Fails closed on anything unexpected.
#
#   --proto '=https'        no ftp/file/gopher, ever
#   --proto-redir '=https'  a 302 cannot downgrade or jump scheme
#   --max-redirs 3          no redirect loops burning the socket
#   --max-filesize          server-declared size cap
#   --fail                  4xx/5xx is an error, not a body to parse
#   (no --insecure, no -k, cert verification stays on)
# Sets FETCH_BODY and LAST_HTTP; returns 0 on success.
#
# The body is returned via a global rather than stdout on purpose. Written as
# `body=$(fetch url)` the whole function runs in a command-substitution
# subshell, so LAST_HTTP is assigned in a child and the parent never sees it --
# every diagnostic then reports "no HTTP response" even for a clean 403.
fetch() {
  local url=$1
  local cap=${2:-$MAX_BYTES}
  local tries=${3:-$RETRIES}
  local attempt=1 resp rc code body
  LAST_HTTP=""

  if ! url_is_allowed "$url"; then
    warn "refusing off-host or non-HTTPS URL"; return 1
  fi

  while (( attempt <= tries )); do
    throttle
    if (( PROGRESS )); then
      printf '  ... %s (attempt %d/%d)\n' "${url#https://}" "$attempt" "$tries" >&2
    fi
    rc=0
    # -w appends the status code so failures are diagnosable. Without it a 403
    # from bot detection is indistinguishable from a dead network -- which is
    # exactly the case that wasted your time.
    #
    # The tr is load-bearing, not tidying. Bash cannot hold a NUL in a
    # variable, so command substitution DELETES them silently (it warns, but
    # only to stderr). ANSI art does contain NULs, and in CP437 a NUL is a
    # blank that occupies a cell. Deleting one shifts every following cell a
    # column to the left, so a piece that relies on the terminal wrapping at
    # 80 shears progressively: fine at the top, further out of true with every
    # row. Converting to a space keeps the cell count exact, which is the
    # thing that actually matters. pipefail is set, so curl\'s exit status
    # still propagates through the pipe.
    resp=$(curl --silent --show-error --location \
                --proto '=https' --proto-redir '=https' \
                --tlsv1.2 \
                --max-redirs "$MAX_REDIRS" \
                --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
                --max-filesize "$cap" \
                --compressed --fail \
                --user-agent "$UA" \
                -H 'Accept: text/html,application/xhtml+xml,application/xml,application/json;q=0.9,*/*;q=0.8' \
                -H 'Accept-Language: en-US,en;q=0.9' \
                -w '\n%{http_code}' \
                -- "$url" 2>/dev/null | LC_ALL=C tr '\000' ' ') || rc=$?

    code=${resp##*$'\n'}
    body=${resp%$'\n'*}
    if [[ $code =~ ^[0-9]{3}$ ]]; then LAST_HTTP=$code; fi

    if (( rc == 0 )); then
      # Belt and braces: --max-filesize only fires when the server declares
      # Content-Length. Chunked responses could otherwise eat memory.
      if (( ${#body} > cap )); then
        warn "response exceeded ${cap} bytes, truncating"
        body=${body:0:cap}
      fi
      FETCH_BODY=$body
      return 0
    fi

    if (( PROGRESS )); then
      printf '      failed (curl exit %d%s)\n' "$rc" "${LAST_HTTP:+, HTTP $LAST_HTTP}" >&2
    fi

    attempt=$(( attempt + 1 ))
    if (( attempt <= tries )); then sleep 2; fi   # short, bounded backoff
  done
  FETCH_BODY=""
  return 1
}

# Turn the last failure into something actionable. Bot detection and a dead
# network look identical from the outside otherwise.
fetch_hint() {
  case ${LAST_HTTP:-} in
    403|429) printf 'HTTP %s: the site is refusing this client; try NFO_UA="..."' "$LAST_HTTP" ;;
    404)     printf 'HTTP 404: that path does not exist on %s' "$HOST" ;;
    5[0-9][0-9]) printf 'HTTP %s: server-side error, try again later' "$LAST_HTTP" ;;
    "")      printf 'no HTTP response at all: DNS, TLS, a proxy, or the size cap' ;;
    *)       printf 'HTTP %s' "$LAST_HTTP" ;;
  esac
}

# ===========================================================================
# SANITISER  -  the important part
# ===========================================================================
#
# Runs under LC_ALL=C so awk is byte-oriented; UTF-8 continuation bytes
# (0x80-0xBF) pass through untouched and cannot be mistaken for an escape
# introducer. Runs BEFORE charset conversion for the same reason.
#
# An OSC that is left unterminated at end-of-line drops the rest of that line;
# its payload continues onto the next line as inert text. That is the safe
# failure direction - the introducer is what is dangerous, not the payload.

readonly AWK_SANITISE='
BEGIN {
  ESC = sprintf("%c", 27)
  BEL = sprintf("%c", 7)
  for (k = 1; k < 256; k++) ORD[sprintf("%c", k)] = k
}
{
  s = $0
  sub(/\r$/, "", s)
  n = length(s); out = ""; col = 0; sgr = 0; i = 1

  while (i <= n) {
    c = substr(s, i, 1)

    # 0x1A is the DOS EOF marker. In artpack files it introduces the SAUCE
    # metadata record, which is binary and must not be rendered as text.
    if (ORD[c] == 26) { print out; exit }

    if (c == ESC) {
      nx = (i < n) ? substr(s, i + 1, 1) : ""

      if (nx == "[") {                       # CSI - allow SGR only
        j = i + 2; par = ""; itm = ""
        while (j <= n) { v = ORD[substr(s, j, 1)]
                         if (v >= 48 && v <= 63) { par = par substr(s, j, 1); j++ } else break }
        while (j <= n) { v = ORD[substr(s, j, 1)]
                         if (v >= 32 && v <= 47) { itm = itm substr(s, j, 1); j++ } else break }
        if (j <= n) {
          fin = substr(s, j, 1)
          if (KEEPCOLOUR && fin == "m" && itm == "" && par ~ /^[0-9;]*$/) {
            out = out ESC "[" par "m"; sgr = 1
          }
          # CUF (cursor forward) rewritten as literal spaces. ANSI art uses it
          # constantly for layout, and unlike CUP/CUU it can only move right
          # within the current line -- it cannot reach the header or overwrite
          # what is already on screen. Turning it into spaces keeps even that
          # limited movement out of the terminal. Capped so a crafted
          # "ESC[999999C" cannot balloon the line.
          else if (fin == "C" && itm == "" && par ~ /^[0-9]*$/) {
            nsp = (par == "") ? 1 : par + 0
            if (nsp > 200) nsp = 200
            for (t = 0; t < nsp; t++) out = out " "
            col += nsp
          }
          i = j + 1
        } else {
          i = n + 1                          # unterminated CSI, discard rest
        }
        continue
      }

      if (nx == "]" || nx == "P" || nx == "X" || nx == "^" || nx == "_") {
        j = i + 2                            # OSC / DCS / SOS / PM / APC
        while (j <= n) {
          cj = substr(s, j, 1)
          if (nx == "]" && cj == BEL) { j++; break }
          if (cj == ESC && j < n && substr(s, j + 1, 1) == "\\") { j += 2; break }
          j++
        }
        i = j
        continue
      }

      # Everything else is ESC + optional intermediates (0x20-0x2F) + one
      # final byte. Charset designators like ESC ( 0 are three bytes, so a
      # blind two-byte skip would leak the "0" as literal text.
      j = i + 1
      while (j <= n) { v = ORD[substr(s, j, 1)]
                       if (v >= 32 && v <= 47) j++; else break }
      i = j + 1
      continue
    }

    v = ORD[c]
    if (v == 9) {                            # TAB -> spaces to the next stop
      pad = 8 - (col % 8)
      for (t = 0; t < pad; t++) out = out " "
      col += pad; i++; continue
    }
    if (v < 32 || v == 127) { i++; continue }  # every other C0, gone

    out = out c; col++; i++
  }

  if (col > MAXW) MAXW = col
  if (sgr) out = out ESC "[0m"               # no colour bleed past EOL
  print out
}
END { if (WIDTHFILE) print MAXW > "/dev/stderr" }
'

# ===========================================================================
# ANSI CANVAS RENDERER
# ===========================================================================
#
# .ANS art is not lines of text -- it is a stream of terminal commands. Two
# properties broke the naive line-based approach:
#
#   * Many files have few or no newlines. The artist writes 240 characters and
#     relies on the terminal WRAPPING at column 80 to form three rows. With
#     autowrap off (which we need, or long lines desync the scroll maths)
#     everything past the right edge is simply lost.
#   * Layout is drawn with cursor motion and erase-line, not spaces. Strip
#     ESC[K / ESC[H / ESC[A and the picture collapses.
#
# So instead of stripping those sequences, this INTERPRETS them into an
# off-screen character grid and prints the finished rows. That is both more
# faithful and safer than the strip-everything approach:
#
#   - Every cursor operation is clamped to the canvas (1..MAXROWS x 1..W).
#     Hostile absolute positioning can overwrite the art, and nothing else --
#     it cannot reach the header, the status line, or the shell prompt.
#   - The OUTPUT contains only SGR. Same guarantee as before: no OSC, no DCS,
#     no cursor addressing ever reaches the real terminal.
#   - MAXROWS and MAXCOLS bound the memory a crafted file can make us allocate
#     (ESC[999999B would otherwise be an allocation bomb).
#
# Runs under LC_ALL=C on raw CP437 bytes, BEFORE charset conversion, so one
# byte is one cell and no multi-byte sequence can smuggle an introducer past.
readonly AWK_ANSI='
function u2(a, b)    { return sprintf("%c%c", a, b) }
function u3(a, b, c) { return sprintf("%c%c%c", a, b, c) }
BEGIN {
  ESC = sprintf("%c", 27); BEL = sprintf("%c", 7); SUB = sprintf("%c", 26)
  for (k = 1; k < 256; k++) ORD[sprintf("%c", k)] = k

  # CP437 gives the C0 range and 0x7F printable glyphs, and artists use them:
  # 0x7F is a house, not DEL. glibc iconv maps them straight to the matching
  # control code points instead, so the substitution has to happen here.
  # Only ESC, CR, LF, TAB and SUB keep their control meaning -- an artist
  # cannot use those five, because a terminal would act on them.
  G[1]  = u3(226,152,186); G[2]  = u3(226,152,187)   # smiling faces
  G[3]  = u3(226,153,165); G[4]  = u3(226,153,166)   # heart, diamond
  G[5]  = u3(226,153,163); G[6]  = u3(226,153,160)   # club, spade
  G[7]  = u3(226,128,162); G[8]  = u3(226,151,152)   # bullet, inverse bullet
  G[11] = u3(226,153,130); G[12] = u3(226,153,128)   # male, female
  G[14] = u3(226,153,171); G[15] = u3(226,152,188)   # note, sun
  G[16] = u3(226,150,186); G[17] = u3(226,151,132)   # right, left triangle
  G[18] = u3(226,134,149); G[19] = u3(226,128,188)   # up-down, double bang
  G[20] = u2(194,182);     G[21] = u2(194,167)       # pilcrow, section
  G[22] = u3(226,150,172); G[23] = u3(226,134,168)   # rectangle, up-down bar
  G[24] = u3(226,134,145); G[25] = u3(226,134,147)   # up, down arrow
  G[28] = u3(226,136,159); G[29] = u3(226,134,148)   # right angle, left-right
  G[30] = u3(226,150,178); G[31] = u3(226,150,188)   # up, down triangle
  G[127] = u3(226,140,130)                           # house

  # The 16 CGA/VGA colours the art was actually drawn against, as 24-bit
  # values. Dithering works by blending two of these through the density of
  # a shade glyph, so the blend only reads correctly if the endpoints are the
  # real ones -- a themed terminal palette shifts every gradient.
  # Indexed by the SGR number (31 = red, 34 = blue), NOT by the CGA hardware
  # order (1 = blue, 4 = red). The two disagree on red/blue and on
  # brown/cyan, so filling this in hardware order and indexing it with an SGR
  # code silently swaps them -- and in dithered art that inverts entire
  # gradients rather than looking obviously wrong.
  PAL[0]  = "0;0;0";       PAL[1]  = "170;0;0"      # black, red
  PAL[2]  = "0;170;0";     PAL[3]  = "170;85;0"     # green, brown
  PAL[4]  = "0;0;170";     PAL[5]  = "170;0;170"    # blue, magenta
  PAL[6]  = "0;170;170";   PAL[7]  = "170;170;170"  # cyan, light grey
  PAL[8]  = "85;85;85";    PAL[9]  = "255;85;85"    # dark grey, bright red
  PAL[10] = "85;255;85";   PAL[11] = "255;255;85"   # bright green, yellow
  PAL[12] = "85;85;255";   PAL[13] = "255;85;255"   # bright blue, bright mag
  PAL[14] = "85;255;255";  PAL[15] = "255;255;255"  # bright cyan, white
  if (VGA) NEUTRAL = ESC "[0;38;2;" PAL[7] ";48;2;" PAL[0] "m"; else NEUTRAL = ""
  if (MAXROWS + 0 <= 0) MAXROWS = 1000    # overridden by -v from the caller
  if (MAXCOLS + 0 <= 0) MAXCOLS = 320    # overridden by -v from the caller
  SGRRE = ESC "\\[[0-9;]*m"
  CSIRE = ESC "\\[[0-9;]*[A-Za-z]"
  buf = ""; MOTION = 0; LONGEST = 0; NLINES = 0
}
{
  buf = buf $0 "\n"
  # Does this file actually use cursor motion? Strip the SGRs and see if any
  # CSI is left. Decides the canvas width below.
  NLINES++
  if (!MOTION) { t = $0; gsub(SGRRE, "", t); if (t ~ CSIRE) MOTION = 1 }
  # Longest line measured with ALL escape sequences removed, not just SGR:
  # cursor codes occupy no cells either, and counting them inflates the
  # inferred width.
  u = $0; gsub(CSIRE, "", u)
  cells = 0
  for (z = 1; z <= length(u); z++) { zz = ORD[substr(u, z, 1)]; if (zz < 128 || zz >= 192) cells++ }
  if (cells > LONGEST) LONGEST = cells
}
END {
  p = index(buf, SUB)                 # SAUCE metadata record starts at 0x1A
  if (p > 0) buf = substr(buf, 1, p - 1)

  # Canvas width when the caller did not supply one.
  #
  #   no line breaks at all -> the piece relies on autowrap, so 80
  #   longest line  > 80    -> it is authored wider than 80; use that
  #   otherwise             -> 80
  #
  # The old rule forced 80 whenever cursor motion was present, which quietly
  # sliced every 132- or 160-column piece in half and interleaved the halves.
  W = WIDTH + 0
  if (W <= 0) {
    # One enormous run with no break: art that relies on the terminal wrapping
    # at 80. So is a single record that uses cursor codes.
    if (LONGEST > MAXCOLS)          W = 80
    else if (NLINES <= 1 && MOTION) W = 80
    # Otherwise take the longest line. Folding is the worse error to make on
    # unknown content: a wide .nfo that gets folded is unreadable, whereas one
    # that overflows the terminal can still be read by widening the window.
    else if (LONGEST > 80)          W = LONGEST
    else                            W = 80
  }
  if (W > MAXCOLS) W = MAXCOLS
  if (W < 1) W = 1

  n = length(buf)
  r = 1; c = 1; maxr = 1; sr = 1; sc = 1; pend = 0
  bold = 0; blink = 0; rev = 0; fg = ""; bg = ""; cur = ""
  i = 1

  while (i <= n) {
    ch = substr(buf, i, 1); v = ORD[ch]

    if (ch == ESC) {
      nx = (i < n) ? substr(buf, i + 1, 1) : ""

      if (nx == "[") {
        j = i + 2; par = ""; itm = ""
        while (j <= n) { vv = ORD[substr(buf, j, 1)]
                         if (vv >= 48 && vv <= 63) { par = par substr(buf, j, 1); j++ } else break }
        while (j <= n) { vv = ORD[substr(buf, j, 1)]
                         if (vv >= 32 && vv <= 47) { itm = itm substr(buf, j, 1); j++ } else break }
        if (j > n) { i = n + 1; continue }
        fin = substr(buf, j, 1); i = j + 1

        # A pending wrap has to be resolved BEFORE a cursor sequence is
        # applied, not just cleared.
        #
        # DOS ANSI.SYS wraps the instant the last column is written, so art
        # that fills a row and then says ESC[11C means "column 12 of the next
        # row". A strict VT100 keeps the cursor parked at the last column and
        # lets CUF clamp there, which puts that content 68 columns adrift.
        # But VT100 is right about CR/LF: ANSI.SYS turns a full row followed
        # by CRLF into a blank line, and art written that way clearly does not
        # want one.
        #
        # So: resolve the wrap for cursor sequences and printable characters,
        # cancel it for CR and LF. That is the only reading under which both
        # authoring styles come out as their artist drew them.
        if (HYBRID && fin != "m" && pend) {
          c = 1; r++; pend = 0
          if (r > MAXROWS) r = MAXROWS
        }
        np = split(par, P, ";")
        a1 = (np >= 1 && P[1] != "") ? P[1] + 0 : 0
        a2 = (np >= 2 && P[2] != "") ? P[2] + 0 : 0

        if (fin == "m" && itm == "" && par ~ /^[0-9;]*$/) {
          if (np == 0 || par == "") { bold=0; blink=0; rev=0; fg=""; bg="" }
          for (k = 1; k <= np; k++) {
            code = (P[k] == "") ? 0 : P[k] + 0
            if (code == 0)       { bold=0; blink=0; rev=0; fg=""; bg="" }
            else if (code == 1)  bold = 1
            else if (code == 5)  blink = 1
            else if (code == 7)  rev = 1
            else if (code == 22) bold = 0
            else if (code == 25) blink = 0
            else if (code == 27) rev = 0
            else if (code == 39) fg = ""
            else if (code == 49) bg = ""
            else if ((code >= 30 && code <= 37) || (code >= 90 && code <= 97))   fg = code
            else if ((code >= 40 && code <= 47) || (code >= 100 && code <= 107)) bg = code
            else if (code == 38 || code == 48) {
              sub2 = (P[k+1] == "") ? 0 : P[k+1] + 0
              if (sub2 == 5)      { val = code ";5;" (P[k+2] + 0); k += 2 }
              else if (sub2 == 2) { val = code ";2;" (P[k+2]+0) ";" (P[k+3]+0) ";" (P[k+4]+0); k += 4 }
              else { k += 1; continue }
              if (code == 38) fg = val; else bg = val
            }
          }
          # iCE colours. From the mid-90s on, artists stopped using SGR 5 as
          # blink and used it as the high bit of the BACKGROUND, giving 16
          # background colours instead of 8. Passing the 5 through makes a
          # modern terminal literally blink those cells, so parts of a picture
          # flicker in and out and rows appear to lose their background.
          # Fold it into a bright background instead, which is what every
          # ANSI viewer does. --blink keeps the literal reading.
          bgout = bg
          if (blink && ICE) {
            b = (bg == "") ? 40 : bg + 0
            if (b >= 40 && b <= 47) bgout = b + 60     # 40-47 -> 100-107
          }

          if (VGA && fg !~ /;/ && bgout !~ /;/) {
            # SGR 1 in DOS ANSI means BRIGHT FOREGROUND, not a heavier font.
            # Emitting it as bold and hoping the terminal brightens is a
            # coin flip, and it is the difference between a shade glyph
            # reading as light red or dark red. Resolve it to an index here
            # and emit the real 24-bit colour.
            if (fg == "") fi = 7
            else { fi = fg + 0; if (fi >= 90) fi = fi - 90 + 8; else fi = fi - 30 }
            if (bold) fi = fi + 8
            if (fi < 0) fi = 0; if (fi > 15) fi = 15

            if (bgout == "") bi = 0
            else { bi = bgout + 0; if (bi >= 100) bi = bi - 100 + 8; else bi = bi - 40 }
            if (bi < 0) bi = 0; if (bi > 15) bi = 15

            if (rev) { swap = fi; fi = bi; bi = swap }

            cur = ESC "[0"
            if (blink && !ICE) cur = cur ";5"
            cur = cur ";38;2;" PAL[fi] ";48;2;" PAL[bi] "m"
          } else {
            cur = ESC "[0"
            if (bold) cur = cur ";1"
            if (blink && !ICE) cur = cur ";5"
            if (rev)         cur = cur ";7"
            if (fg != "")    cur = cur ";" fg
            if (bgout != "") cur = cur ";" bgout
            cur = cur "m"
            if (cur == ESC "[0m") cur = ""
          }
          if (!KEEPCOLOUR) cur = ""
        }
        else if (fin == "A") r -= (a1 < 1 ? 1 : a1)
        else if (fin == "B") r += (a1 < 1 ? 1 : a1)
        else if (fin == "C") c += (a1 < 1 ? 1 : a1)
        else if (fin == "D") c -= (a1 < 1 ? 1 : a1)
        else if (fin == "E") { r += (a1 < 1 ? 1 : a1); c = 1 }
        else if (fin == "F") { r -= (a1 < 1 ? 1 : a1); c = 1 }
        else if (fin == "G") c = (a1 < 1 ? 1 : a1)
        else if (fin == "H" || fin == "f") { r = (a1 < 1 ? 1 : a1); c = (a2 < 1 ? 1 : a2) }
        else if (fin == "s") { sr = r; sc = c }
        else if (fin == "u") { r = sr; c = sc }
        else if (fin == "K") {                       # erase in line
          x1 = (a1 == 0) ? c : 1
          x2 = (a1 == 1) ? c : W
          for (x = x1; x <= x2; x++) { CH[r "," x] = " "; AT[r "," x] = cur }
          if (bg != "" && r > maxr) maxr = r         # a coloured bar IS content
        }
        else if (fin == "J") {                       # erase in display
          if (a1 == 2) { split("", CH); split("", AT); maxr = 1; r = 1; c = 1 }
          else if (a1 == 0) {
            for (y = r; y <= maxr; y++)
              for (x = (y == r ? c : 1); x <= W; x++) { CH[y "," x] = " "; AT[y "," x] = cur }
          } else if (a1 == 1) {
            for (y = 1; y <= r; y++)
              for (x = 1; x <= (y == r ? c : W); x++) { CH[y "," x] = " "; AT[y "," x] = cur }
          }
        }
        # Anything else is ignored. Clamp unconditionally: this is the line
        # that makes hostile cursor motion harmless.
        if (fin != "m") pend = 0     # SGR must NOT cancel a pending wrap
                                     # (already resolved above when HYBRID)
        if (r < 1) r = 1; if (r > MAXROWS) r = MAXROWS
        if (c < 1) c = 1; if (c > W) c = W
        continue
      }

      if (nx == "]" || nx == "P" || nx == "X" || nx == "^" || nx == "_") {
        j = i + 2                                    # OSC / DCS / SOS / PM / APC
        while (j <= n) {
          cj = substr(buf, j, 1)
          if (nx == "]" && cj == BEL) { j++; break }
          if (cj == ESC && j < n && substr(buf, j + 1, 1) == "\\") { j += 2; break }
          j++
        }
        i = j; continue
      }

      j = i + 1                                      # ESC + intermediates + final
      while (j <= n) { vv = ORD[substr(buf, j, 1)]; if (vv >= 32 && vv <= 47) j++; else break }
      i = j + 1
      continue
    }

    if (v == 10) { r++; c = 1; pend = 0; if (r > MAXROWS) r = MAXROWS; i++; continue }
    if (v == 13) { c = 1; pend = 0; i++; continue }
    if (v == 9)  { c += 8 - ((c - 1) % 8); pend = 0
                   if (c > W) { c = W; pend = 1 }
                   i++; continue }

    # One cell may be several bytes. The input is UTF-8 by this point, so a
    # lead byte and its continuations are consumed together -- a cell is never
    # split, and a continuation byte can never be mistaken for an introducer.
    glyph = ch; step = 1
    if (v in G) {
      glyph = G[v]
    } else if (v < 32) {
      i++; continue                       # a control with no CP437 glyph
    } else if (v >= 194 && v <= 244) {
      if      (v <= 223) step = 2
      else if (v <= 239) step = 3
      else               step = 4
      if (i + step - 1 > n) { i++; continue }
      glyph = substr(buf, i, step)
    } else if (v >= 128) {
      i++; continue                       # stray continuation byte
    }

    # DEFERRED WRAP, the way a real terminal does it.
    #
    # Writing the last column does NOT move to the next row; it parks the
    # cursor there and raises a pending-wrap flag. The wrap only happens if
    # another printable character arrives. A CR or LF cancels it.
    #
    # Wrapping eagerly instead is subtly catastrophic for ANSI art: a line of
    # exactly W characters followed by CRLF advances one row for the wrap and
    # another for the LF, so every row of the picture gets a blank row after
    # it and the file appears twice as tall as it is.
    if (pend) { c = 1; r++; pend = 0; if (r > MAXROWS) r = MAXROWS }
    CH[r "," c] = glyph; AT[r "," c] = cur
    if (r > maxr) maxr = r
    if (c >= W) pend = 1; else c++
    i += step
  }

  # Emit rows. SGR is written only when the attribute actually changes, so the
  # output is compact, and each row is closed with a reset so colour cannot
  # bleed into the header or the next slide.
  for (row = 1; row <= maxr; row++) {
    last = 0
    for (col = W; col >= 1; col--) {
      key = row "," col
      if (key in CH) {
        if (CH[key] != " " || (AT[key] != "" && AT[key] != NEUTRAL)) { last = col; break }
      }
    }
    line = ""; prev = ""
    for (col = 1; col <= last; col++) {
      key = row "," col
      a  = (key in AT) ? AT[key] : ""
      cc = (key in CH) ? CH[key] : " "
      if (a != prev) { line = line (a == "" ? ESC "[0m" : a); prev = a }
      line = line cc
    }
    if (prev != "") line = line ESC "[0m"
    print line
  }
}
'

# $1 = canvas width, 0 = auto (80 if the file uses cursor motion, else as wide
# as its longest line). Callers force 80 for .ANS, where 80 columns is the
# authoring convention regardless of whether that particular file happens to
# use motion -- the heuristic alone would leave an SGR-only .ANS unwrapped.
render_ansi() {
  local w=${1:-0}
  # Per-file iCE from SAUCE by default, but --blink is authoritative wherever
  # the call comes from: enforcing it here rather than at each call site means
  # a caller that never went through load_nfo cannot quietly ignore it.
  local ice=${2:-$CUR_ICE}
  if (( ! ICE_COLOURS )); then ice=0; fi
  LC_ALL=C awk -v KEEPCOLOUR="$KEEPCOLOUR" -v WIDTH="$w" -v ICE="$ice" \
               -v HYBRID="$HYBRID_WRAP" -v VGA="$VGA_PALETTE" \
               -v MAXCOLS="$ART_MAX_COLS" -v MAXROWS="$ART_MAX_ROWS" -- "$AWK_ANSI"
}

sanitise_stream() {
  LC_ALL=C awk -v KEEPCOLOUR="$KEEPCOLOUR" -- "$AWK_SANITISE"
}

# Detect the charset and normalise to UTF-8.
#
# NFO art is nearly always CP437 (the DOS box-drawing set). Some newer files
# are already UTF-8. Rule: high bytes present AND the whole thing is valid
# UTF-8 -> treat as UTF-8; otherwise CP437. Pure ASCII goes either way.
to_utf8() {
  local raw=$1 highbytes
  highbytes=$(LC_ALL=C printf '%s' "$raw" | LC_ALL=C tr -d '\000-\177' | head -c 1)

  if [[ -z $highbytes ]]; then
    printf '%s' "$raw"; return 0
  fi
  if (( ! HAVE_ICONV )); then
    printf '%s' "$raw"; return 0        # no iconv: render as-is, art may smear
  fi
  if printf '%s' "$raw" | iconv -f UTF-8 -t UTF-8 >/dev/null 2>&1; then
    printf '%s' "$raw"                  # already valid UTF-8
  else
    printf '%s' "$raw" | iconv -f CP437 -t UTF-8//TRANSLIT 2>/dev/null \
      || printf '%s' "$raw"
  fi
}

# Widest VISIBLE line, in terminal columns.
#
# Two things make this non-obvious. The lines still carry SGR escapes, which
# occupy no columns, so they are stripped before measuring. And the text is
# UTF-8 by this point, so a byte count would over-report every box-drawing
# character; UTF-8 continuation bytes (0x80-0xBF) are therefore not counted.
# Doing it this way is exact and behaves the same in gawk, mawk and busybox
# awk, none of which agree about multi-byte length().
#
# Caveat: assumes every character is one column wide. True for CP437 art;
# would be wrong for East Asian wide characters, which do not occur here.
visible_width() {
  LC_ALL=C awk -v ESC="$(printf '\033')" '
    BEGIN { for (k = 1; k < 256; k++) ORD[sprintf("%c", k)] = k }
    {
      s = $0
      gsub(ESC "\\[[0-9;]*m", "", s)
      n = length(s); w = 0
      for (i = 1; i <= n; i++) { v = ORD[substr(s, i, 1)]; if (v < 128 || v >= 192) w++ }
      if (w > MAXW) MAXW = w
    }
    END { print MAXW + 0 }'
}

# ===========================================================================
# HTML / JSON EXTRACTION
# ===========================================================================

# ===========================================================================
# DISCOVERY  (16colo.rs)
# ===========================================================================
#
#   GET api.16colo.rs/v1/year/<year>  -> results[].name          = pack names
#   GET api.16colo.rs/v1/pack/<pack>  -> results[].files{}        = filenames
#   GET 16colo.rs/pack/<pack>/raw/<file>                          = the bytes
#
# The raw path is inferred from the thumbnail URIs the pack endpoint returns
# (/pack/<pack>/tn/... and /pack/<pack>/x1/...), where "raw" is the sibling
# segment. It is verified at runtime rather than assumed: if the fetch fails
# the file is skipped and the next one is tried, and --probe reports it
# explicitly.
#
# No jq dependency, so JSON is scraped for just the keys we need.
# That is fine here because every extracted value is then run through a strict
# allowlist before it can reach a URL -- the parser being loose does not widen
# the trust boundary.

# Split the JSON at each occurrence of a key and pull the value plus a
# sibling array out of the same segment. Segments are bounded by the next
# occurrence of the same key, so one record cannot borrow another record's
# metadata. Still no jq dependency; every extracted value is allowlisted
# before it reaches a URL or the terminal.
readonly AWK_RECORDS='
{ buf = buf $0 }
END {
  n = split(buf, A, KEY)
  for (i = 2; i <= n; i++) {
    seg = A[i]
    q = index(seg, "\"")
    if (q < 2) continue
    name = substr(seg, 1, q - 1)
    meta = ""
    if (match(seg, METARE)) {
      meta = substr(seg, RSTART + MLEN, RLENGTH - MLEN - 1)
      gsub(/"/, "", meta)
      gsub(/,/, ", ", meta)
    }
    # Optional third field: the pixel width of the 1:1 render, which is how
    # 16colo.rs reports the true character width of a piece.
    px = ""
    if (XKEY != "" && match(seg, XKEY)) {
      sub_ = substr(seg, RSTART, RLENGTH)
      if (match(sub_, /"width":[0-9]+/)) px = substr(sub_, RSTART + 8, RLENGTH - 8)
    }
    print name "\t" meta "\t" px
  }
}'

# year JSON  -> "packname<TAB>groups"
parse_year() {
  LC_ALL=C awk -v KEY='"name":"' -v METARE='"groups":\\[[^]]*\\]' -v MLEN=10 \
           -v XKEY='' -- "$AWK_RECORDS"
}

# pack JSON  -> "filename<TAB>artists"
# pack JSON -> "filename<TAB>artists<TAB>x1pixels<TAB>saucewidth<TAB>icecolors"
#
# The SAUCE record states the width outright, which retires the whole
# pixels-divided-by-8-or-9 guess: 1440 px is 180 columns at 8 px AND 160 at
# 9 px, both divide exactly, and no arithmetic can choose between them.
# The pixel reading stays as a fallback for records with no SAUCE.
readonly AWK_PACKFILES='
{ buf = buf $0 }
END {
  n = split(buf, A, "\"raw\":\"")
  for (i = 2; i <= n; i++) {
    seg = A[i]
    q = index(seg, "\"")
    if (q < 2) continue
    name = substr(seg, 1, q - 1)

    artists = ""
    if (match(seg, /"artists":\[[^]]*\]/)) {
      artists = substr(seg, RSTART + 11, RLENGTH - 12)
      gsub(/"/, "", artists); gsub(/,/, ", ", artists)
    }

    px = ""
    if (match(seg, /"x1":[^}]*}/)) {
      o = substr(seg, RSTART, RLENGTH)
      if (match(o, /"width":[0-9]+/)) px = substr(o, RSTART + 8, RLENGTH - 8)
    }

    sw = ""; ice = ""; sh = ""
    if (match(seg, /"sauce":[^}]*}/)) {
      o = substr(seg, RSTART, RLENGTH)
      if (match(o, /"width":[0-9]+/))      sw  = substr(o, RSTART + 8, RLENGTH - 8)
      if (match(o, /"height":[0-9]+/))     sh  = substr(o, RSTART + 9, RLENGTH - 9)
      if (match(o, /"icecolors":[a-z]+/))  ice = substr(o, RSTART + 12, RLENGTH - 12)
    }

    print name "\t" artists "\t" px "\t" sw "\t" ice "\t" sh
  }
}'

parse_pack() { LC_ALL=C awk -- "$AWK_PACKFILES"; }

# Characters per row from the pixel width of the archive\'s 1:1 render.
#
# Ambiguous on its own: ansilove draws with either a 9-pixel IBM VGA font or
# an 8-pixel font, depending on what the file asks for, so 720px is 80 columns
# at 9px OR 90 at 8px. Both divide exactly. Resolve it by preferring whichever
# candidate is a standard art width -- 90-column art essentially does not
# exist, 80 is everywhere.
#
#   720 -> 80  (720/9, standard)      640 -> 80  (640/8; 640/9 is not exact)
#  1440 -> 160 (1440/9, standard)    1280 -> 160 (1280/8)
#   352 -> 44  (352/8; no standard candidate, so fall through to the 8px read)
cols_from_px() {
  local px=$1 w9=0 w8=0 c
  if (( px % 9 == 0 )); then w9=$(( px / 9 )); fi
  if (( px % 8 == 0 )); then w8=$(( px / 8 )); fi
  for c in "$w9" "$w8"; do
    case $c in 80|132|160) printf %s "$c"; return 0 ;; esac
  done
  if (( w8 > 0 )); then printf %s "$w8"; return 0; fi
  if (( w9 > 0 )); then printf %s "$w9"; return 0; fi
  return 1
}

# Metadata is untrusted remote text going straight into the header -- exactly
# the spoofing surface the renderer exists to protect. Strict character
# allowlist and a hard length cap, not an escape filter.
safe_meta() {
  local t
  t=$(printf '%s' "$1" | LC_ALL=C tr -cd 'A-Za-z0-9 ._,()!&+@/-')
  printf '%s' "${t:0:${2:-48}}"
}


# Load and cache one year of packs. Cached because the main loop re-rolls the
# year for every pack: sticking to one year for a whole session, as the first
# version did, meant you only ever saw one slice of the archive.
ensure_year() {
  local year=$1 name grp acc=""
  if [[ -n ${YEAR_CACHE[$year]:-} ]]; then return 0; fi
  if (( TERM_READY )); then show_loading "loading the ${year} pack list ..."; fi
  if ! fetch "${API_URL}/year/${year}" "$MAX_BYTES_INDEX" "$DISCOVERY_RETRIES"; then
    return 1
  fi
  while IFS=$'\t' read -r name grp; do
    if pack_is_valid "$name"; then
      acc+="${name}"$'\n'
      PACK_GROUP[$name]=$(safe_meta "$grp" 32)
    fi
  done < <(printf '%s' "$FETCH_BODY" | parse_year)
  if [[ -z $acc ]]; then return 1; fi
  YEAR_CACHE[$year]=$acc
  return 0
}

# Random year, then a random pack from it. PICKED holds the pack name.
next_pack() {
  local attempt=1 year now
  now=$(date +%Y)
  while (( attempt <= 5 )); do
    year=$(( YEAR_MIN + (((RANDOM << 15) | RANDOM) % (now - YEAR_MIN + 1)) ))
    if ensure_year "$year"; then
      mapfile -t PACKS < <(printf '%s' "${YEAR_CACHE[$year]}")
      if pick_into ${PACKS[@]+"${PACKS[@]}"}; then YEAR=$year; return 0; fi
    fi
    attempt=$(( attempt + 1 ))
  done
  return 1
}

# Startup check only: prove the API answers and that we can parse it.
build_pool() {
  local attempt=1 now year
  now=$(date +%Y)
  while (( attempt <= 4 )); do
    year=$(( YEAR_MIN + (((RANDOM << 15) | RANDOM) % (now - YEAR_MIN + 1)) ))
    if (( PROGRESS )); then printf 'trying year %s...\n' "$year" >&2; fi
    if ensure_year "$year"; then
      mapfile -t PACKS < <(printf '%s' "${YEAR_CACHE[$year]}")
      if (( PROGRESS )); then printf '  %s: %d packs\n' "$year" "${#PACKS[@]}" >&2; fi
      YEAR=$year; return 0
    fi
    attempt=$(( attempt + 1 ))
  done
  return 1
}

# Fill FILES with the renderable files of one pack, and FILE_ARTIST with the
# credit for each.
load_pack() {
  local pack=$1 fn art px sw ice sh
  local -a clean=()
  FILES=(); FILE_ARTIST=(); FILE_COLS=(); FILE_PX=(); FILE_ICE=(); FILE_SAUCE_H=()
  pack_is_valid "$pack" || return 1

  # ?sauce=true asks the archive for the SAUCE record. Harmless if the
  # parameter is not honoured: the fields are simply absent and the pixel
  # fallback below takes over.
  fetch "${API_URL}/pack/${pack}?sauce=true" "$MAX_BYTES_INDEX" 1 || return 1
  while IFS=$'\t' read -r fn art px sw ice sh; do
    if ! file_is_valid "$fn"; then continue; fi
    if [[ ${fn,,} =~ $TEXT_EXT_RE ]]; then
      clean+=("$fn")
      FILE_ARTIST[$fn]=$(safe_meta "$art" 32)
      if [[ $ice == "true" || $ice == "false" ]]; then FILE_ICE[$fn]=$ice; fi
      if [[ $px =~ ^[0-9]+$ ]]; then FILE_PX[$fn]=$px; fi
      if [[ $sh =~ ^[0-9]+$ ]]; then FILE_SAUCE_H[$fn]=$sh; fi

      # Width, best source first. SAUCE states it; the pixel width only
      # implies it, and ambiguously.
      if [[ $sw =~ ^[0-9]+$ ]] && (( sw >= 20 && sw <= ART_MAX_COLS )); then
        FILE_COLS[$fn]=$sw
      elif [[ $px =~ ^[0-9]+$ ]] && (( px >= 160 && px <= ART_MAX_COLS * 9 )); then
        local cols
        if cols=$(cols_from_px "$px"); then
          if (( cols >= 20 && cols <= ART_MAX_COLS )); then FILE_COLS[$fn]=$cols; fi
        fi
      fi
    fi
  done < <(printf '%s' "$FETCH_BODY" | parse_pack)

  FILES=(${clean[@]+"${clean[@]}"})
  (( ${#FILES[@]} > 0 ))
}

# Fetch one file and populate NFO_LINES. Returns non-zero if it is not usable.
load_nfo() {
  local pack=$1 file=$2 text
  pack_is_valid "$pack" || return 1
  file_is_valid "$file" || return 1

  fetch "${BASE}/pack/${pack}/raw/${file}" || return 1
  CUR_RAW=$FETCH_BODY

  # Render on the canvas FIRST, convert charset second: a filter that runs
  # after decoding can be walked past with a crafted multi-byte sequence.
  # Canvas width, best source first:
  #   1. --width, if the user pinned it
  #   2. the API's 1:1 render width, which is authoritative per file
  #   3. 80 for art, because art that relies on autowrap MUST be read at the
  #      width it was drawn at, and that width is 80 for anything from the
  #      DOS era. Inferring from the longest line is fine for text but wrong
  #      here: one stray long line picks 90 instead of 80, and every row of a
  #      wrap-reliant piece then drifts ten columns further right than the
  #      last -- the picture shears diagonally instead of tiling.
  #   4. 0 (infer) only for plain text, where folding is the worse error.
  local w=$NFO_ANSI_WIDTH
  if (( w == 0 )) && [[ -n ${FILE_COLS[$file]:-} ]]; then w=${FILE_COLS[$file]}; fi
  if (( w == 0 )) && [[ ${file,,} =~ [.](ans|asc)$ ]]; then w=80; fi

  # SAUCE also records whether the piece was authored with iCE colours. When
  # it says so, believe it per file rather than applying one global guess:
  # "icecolors: no" means SGR 5 really is blink and folding it into a bright
  # background would be wrong.
  CUR_ICE=$ICE_COLOURS
  case ${FILE_ICE[$file]:-} in
    true)  CUR_ICE=1 ;;
    false) CUR_ICE=0 ;;
  esac
  if (( ! ICE_COLOURS )); then CUR_ICE=0; fi   # --blink still wins
  # Convert to UTF-8 FIRST, then render. The canvas consumes multi-byte
  # sequences atomically, so nothing can be split or re-read as an escape;
  # and it can only substitute the CP437 C0 glyphs once it is emitting UTF-8.
  CUR_W=$w
  text=$(to_utf8 "$CUR_RAW" | render_ansi "$w")

  mapfile -t NFO_LINES < <(printf '%s\n' "$text")

  while (( ${#NFO_LINES[@]} )) && [[ -z ${NFO_LINES[0]//[[:space:]]/} ]]; do
    NFO_LINES=("${NFO_LINES[@]:1}")
  done
  local last
  while (( ${#NFO_LINES[@]} )); do
    last=$(( ${#NFO_LINES[@]} - 1 ))
    if [[ -n ${NFO_LINES[last]//[[:space:]]/} ]]; then break; fi
    unset "NFO_LINES[$last]"          # negative subscripts need bash 4.3+
  done
  NFO_WIDTH=$(printf '%s\n' ${NFO_LINES[@]+"${NFO_LINES[@]}"} | visible_width)
  [[ $NFO_WIDTH =~ ^[0-9]+$ ]] || NFO_WIDTH=0

  (( ${#NFO_LINES[@]} >= 3 ))
}

# Sets PICKED. Deliberately NOT "x=$(pick ...)".
#
# A command substitution is a subshell. It inherits the parent RANDOM state,
# consumes it in the child, and the parent state never advances -- so two
# consecutive picks start from the same seed and repeat. Bash reseeds
# subshells from the pid, which is not nearly random enough: eight picks from
# eight items gave "h h g c h h e h". Setting a global keeps the draw in the
# parent, where the state actually moves.
#
# $RANDOM is 15 bits and is not a CSPRNG -- fine for a slideshow, and stated
# rather than papered over. Two draws are combined so the modulo is not biased
# against a pool larger than 32768.
pick_into() {           # $1.. = elements -> PICKED
  local n=$#
  if (( n == 0 )); then return 1; fi
  local r=$(( ((RANDOM << 15) | RANDOM) % n ))
  shift "$r"
  PICKED=$1
}

# ===========================================================================
# TERMINAL
# ===========================================================================

term_size() {
  ROWS=$(tput lines 2>/dev/null || echo 24)
  COLS=$(tput cols  2>/dev/null || echo 80)
  if (( ROWS < 8 ));  then ROWS=8;  fi
  if (( COLS < 20 )); then COLS=20; fi
}

term_init() {
  if [[ -t 0 && -t 1 ]] && exec 3</dev/tty 2>/dev/null; then
    INTERACTIVE=1
    STTY_SAVE=$(stty -g <&3 2>/dev/null || true)
    [[ -n $STTY_SAVE ]] && stty -echo <&3 2>/dev/null || true
  fi
  term_size
  printf '\e[?1049h'   # alternate screen: your scrollback survives
  printf '\e[?25l'     # hide cursor
  printf '\e[?7l'      # autowrap OFF: terminal wrapping would desynchronise
                       # the scroll arithmetic. Wrapping happens on the canvas
                       # in render_ansi instead, where it is exact.
  printf '\e[2J\e[H'
  TERM_READY=1
}

# Restores the terminal on ANY exit path, including SIGINT and an uncaught
# error. Guarded so it cannot recurse, and so --probe (which never touches the
# terminal) does not spray escape codes at a pipe.
cleanup() {
  local rc=$?
  if (( CLEANED )); then return; fi
  CLEANED=1
  if (( TERM_READY )); then
    printf '\e[r'                  # release scroll region
    printf '\e[0m\e[?7h\e[?25h'    # reset SGR, autowrap, cursor
    printf '\e[?1049l'             # back to the normal screen
    if (( INTERACTIVE )) && [[ -n $STTY_SAVE ]]; then
      stty "$STTY_SAVE" <&3 2>/dev/null || true
    fi
    printf 'nfoslide: %d shown, %d skipped, %d errors\n' \
      "$SHOWN" "$SKIPPED" "$ERRORS"
  fi
  exec 3<&- 2>/dev/null || true
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'term_size' WINCH

# Wait up to $1 seconds for a keypress. Never returns non-zero, so it is safe
# under `set -e`; the outcome lands in KEY_ACTION. `read -t` is a builtin, so
# this is also our sleep - no fork per frame, which matters for a loop that is
# meant to run for hours.
wait_key() {
  local timeout=$1 k="" k2="" k3="" k4=""
  KEY_ACTION="timeout"
  # With no input source a pause could never be lifted, so do not honour it,
  # and never inherit the hour-long pause timeout as a literal sleep.
  if (( ! INTERACTIVE )); then
    PAUSED=0
    if [[ $timeout == "$PAUSE_WAIT" ]]; then timeout=1; fi
    sleep "$timeout"
    return 0
  fi

  # bash distinguishes the two ways read can fail: >128 is the timeout, 1 is
  # EOF. Treating EOF as a timeout would turn the scroll loop into a busy
  # spin at full CPU the moment the tty went away, so drop to non-interactive
  # and sleep instead.
  # IFS= on the read itself: the script narrows IFS globally, but relying on
  # that would make the space key silently vanish if IFS ever changed.
  local rc=0
  IFS= read -rsn1 -t "$timeout" -u 3 k 2>/dev/null || rc=$?
  if (( rc > 128 )); then return 0; fi
  if (( rc != 0 )); then
    INTERACTIVE=0
    PAUSED=0
    if [[ $timeout == "$PAUSE_WAIT" ]]; then timeout=1; fi
    sleep "$timeout"
    return 0
  fi

  case $k in
    q|Q) KEY_ACTION="quit"; return 0 ;;
    " ") KEY_ACTION="pause"; return 0 ;;
    "[") KEY_ACTION="narrower"; return 0 ;;
    "]") KEY_ACTION="wider"; return 0 ;;
    "{") KEY_ACTION="narrower8"; return 0 ;;
    "w"|"W") KEY_ACTION="wrapmode"; return 0 ;;
    "p"|"P") KEY_ACTION="palette"; return 0 ;;
    "}") KEY_ACTION="wider8"; return 0 ;;
    $'\e')
      # Arrows arrive as ESC [ A. Read the rest with a short timeout so a bare
      # ESC does not block, and so a split sequence still reassembles.
      if IFS= read -rsn1 -t 0.06 -u 3 k2 2>/dev/null && [[ $k2 == "[" || $k2 == "O" ]]; then
        IFS= read -rsn1 -t 0.06 -u 3 k3 2>/dev/null || true
        case $k3 in
          A) KEY_ACTION="up" ;;
          B) KEY_ACTION="down" ;;
          D) KEY_ACTION="prev" ;;      # left  = older artwork
          C) KEY_ACTION="next" ;;      # right = newer artwork
          H) KEY_ACTION="home" ;;
          F) KEY_ACTION="end" ;;
          5) KEY_ACTION="pgup"; IFS= read -rsn1 -t 0.06 -u 3 k4 2>/dev/null || true ;;
          6) KEY_ACTION="pgdn"; IFS= read -rsn1 -t 0.06 -u 3 k4 2>/dev/null || true ;;
          *) KEY_ACTION="none" ;;
        esac
      else
        # A bare ESC is ignored rather than treated as skip or quit: a
        # mis-timed arrow should never throw away the slide you are reading.
        KEY_ACTION="none"
      fi
      ;;
    *) KEY_ACTION="skip" ;;
  esac
  return 0
}

# Top-down wipe. Honours a keypress mid-transition so 'q' is never swallowed.
transition() {
  if (( ! SMOOTH )); then printf '\e[2J\e[H'; return; fi
  local r
  for (( r = 1; r <= ROWS; r++ )); do
    printf '\e[%d;1H\e[2K' "$r"
    wait_key 0.006
    if [[ $KEY_ACTION == quit ]]; then return; fi
  done
  printf '\e[H'
}

draw_header() {
  local id=$1 lines=$2 pos=$3 total=$4   # lines kept for call-site symmetry
  local left right pad avail
  left=" ${id}"
  if [[ -n $CUR_META ]]; then left+="  ·  ${CUR_META}"; fi
  # No "N lines" here: [pos/total] on the right already carries it, and the
  # space is better spent on the credit.
  right="[${pos}/${total}]  ↑↓  q:quit "

  # Truncate the left side, never the controls: metadata is remote text and
  # must not be able to push the key hints off screen.
  avail=$(( COLS - ${#right} - 1 ))
  if (( avail < 8 )); then avail=8; fi
  if (( ${#left} > avail )); then left="${left:0:avail-1}…"; fi

  pad=$(( COLS - ${#left} - ${#right} ))
  if (( pad < 1 )); then pad=1; fi
  printf '\e[1;1H\e[2K\e[7m%s%*s%s\e[0m' "$left" "$pad" "" "$right"
  printf '\e[2;1H\e[2K\e[2m%s\e[0m' "$(printf '%*s' "$COLS" '' | tr ' ' '-')"
}

# Pad is recomputed inline on every draw so a resize mid-slide re-centres
# instead of drifting. Deliberately plain arithmetic and no command
# substitution: this runs once per line, i.e. once per scroll frame, and a
# fork there would be a fork per frame for hours.
draw_line() {           # $1 = row, $2 = text
  local pad=$(( (COLS - NFO_WIDTH) / 2 ))
  if (( pad < 0 )) || (( ! CENTRE )); then pad=0; fi
  printf '\e[%d;1H\e[2K%*s%s\e[0m' "$1" "$pad" "" "$2"
}

draw_status() {
  # Pieces authored at 132 or 160 columns are common and now render at their
  # true width, so on a narrow window they get clipped by the right edge.
  # Say so rather than let it look like a rendering fault.
  local warn=""
  if (( CUR_W > 0 )); then warn="  ·  w${CUR_W} []"; fi
  if (( ! HYBRID_WRAP )); then warn="${warn}  ·  strict wrap (w)"; fi
  if (( VGA_PALETTE )); then warn="${warn}  ·  vga (p)"; else warn="${warn}  ·  term (p)"; fi
  if (( NFO_WIDTH > COLS )); then
    warn="${warn}  ·  ${NFO_WIDTH} cols, terminal ${COLS}"
  fi
  printf '\e[%d;1H\e[2K\e[2m %s%s%s\e[0m' "$ROWS" "$HIST_LABEL" "$1" "$warn"
}

# ===========================================================================
# RENDER
# ===========================================================================

# ===========================================================================
# HISTORY
# ===========================================================================
#
# The last HIST_MAX artworks are kept rendered, so left/right is instant and
# costs no requests. Two independent bounds: a count, and a byte budget --
# a 1000x200 canvas with colour can approach a megabyte, and 50 of those on a
# session left running overnight is not something to leave unbounded.

hist_evict() {
  while (( ${#HIST_KEY[@]} > HIST_MAX )) || \
        { (( HIST_BYTES > HIST_BUDGET )) && (( ${#HIST_KEY[@]} > 1 )); }; do
    HIST_BYTES=$(( HIST_BYTES - ${#HIST_TEXT[0]} - ${#HIST_RAW[0]} ))
    HIST_KEY=("${HIST_KEY[@]:1}");  HIST_TEXT=("${HIST_TEXT[@]:1}")
    HIST_META=("${HIST_META[@]:1}"); HIST_W=("${HIST_W[@]:1}")
    HIST_RAW=("${HIST_RAW[@]:1}");  HIST_CW=("${HIST_CW[@]:1}")
    HIST_POS=$(( HIST_POS - 1 ))
  done
  if (( HIST_POS < 0 )); then HIST_POS=0; fi
}

hist_push() {           # $1 key  $2 meta  $3 text  $4 width
  HIST_KEY+=("$1"); HIST_META+=("$2"); HIST_TEXT+=("$3"); HIST_W+=("$4")
  HIST_RAW+=("$CUR_RAW"); HIST_CW+=("$CUR_W")
  HIST_BYTES=$(( HIST_BYTES + ${#3} + ${#CUR_RAW} ))
  HIST_POS=$(( ${#HIST_KEY[@]} - 1 ))
  hist_evict
}

hist_load() {           # $1 index -> NFO_LINES, CUR_META, NFO_WIDTH
  local i=$1
  mapfile -t NFO_LINES < <(printf '%s\n' "${HIST_TEXT[i]}")
  CUR_META=${HIST_META[i]}
  NFO_WIDTH=${HIST_W[i]}
  CUR_RAW=${HIST_RAW[i]}
  CUR_W=${HIST_CW[i]}
}

# Re-render the current artwork on a different canvas without refetching.
# The width guesses above are heuristics over thirty years of files from
# hundreds of artists; when one is wrong the fix should be a keypress, not a
# bug report.
rewidth() {                     # $1 = delta in columns
  local nw=$(( CUR_W + $1 ))
  if (( CUR_W == 0 )); then nw=$(( NFO_WIDTH + $1 )); fi
  if (( nw < 20 )); then nw=20; fi
  if (( nw > ART_MAX_COLS )); then nw=$ART_MAX_COLS; fi
  if [[ -z $CUR_RAW ]]; then return 1; fi

  local text
  text=$(to_utf8 "$CUR_RAW" | render_ansi "$nw")
  mapfile -t NFO_LINES < <(printf '%s\n' "$text")
  NFO_WIDTH=$(printf '%s\n' ${NFO_LINES[@]+"${NFO_LINES[@]}"} | visible_width)
  [[ $NFO_WIDTH =~ ^[0-9]+$ ]] || NFO_WIDTH=0
  CUR_W=$nw

  # Write it back so browsing away and returning keeps the corrected width.
  if (( HIST_POS >= 0 && HIST_POS < ${#HIST_KEY[@]} )); then
    HIST_BYTES=$(( HIST_BYTES - ${#HIST_TEXT[HIST_POS]} + ${#text} ))
    HIST_TEXT[HIST_POS]=$text
    HIST_W[HIST_POS]=$NFO_WIDTH
    HIST_CW[HIST_POS]=$nw
  fi
  return 0
}

hist_is_live() { (( HIST_POS >= ${#HIST_KEY[@]} - 1 )); }

# Body geometry, shared with the redraw helpers below.
SN_TOP=3; SN_BOTTOM=1; SN_BODY=1; SN_OFF=0

redraw_body() {
  local i row
  for (( i = 0; i < SN_BODY; i++ )); do
    row=$(( SN_TOP + i ))
    if (( SN_OFF + i < ${#NFO_LINES[@]} )); then
      draw_line "$row" "${NFO_LINES[SN_OFF + i]}"
    else
      printf '\e[%d;1H\e[2K' "$row"
    fi
  done
}

# One line down: let the terminal scroll the region and paint only the new
# bottom row. No repaint, so no flicker.
scroll_down_one() {
  printf '\e[%d;1H\n' "$SN_BOTTOM"
  local idx=$(( SN_OFF + SN_BODY - 1 ))
  if (( idx < ${#NFO_LINES[@]} )); then
    draw_line "$SN_BOTTOM" "${NFO_LINES[idx]}"
  else
    printf '\e[%d;1H\e[2K' "$SN_BOTTOM"
  fi
}

# One line up: reverse index at the top of the region, then paint the new top.
scroll_up_one() {
  printf '\e[%d;1H\eM' "$SN_TOP"
  draw_line "$SN_TOP" "${NFO_LINES[SN_OFF]}"
}

show_nfo() {
  local id=$1
  local total=${#NFO_LINES[@]}
  local top=3
  local bottom=$(( ROWS - 1 ))
  local body=$(( bottom - top + 1 ))
  if (( body < 1 )); then body=1; fi
  local keep_off=0
  if (( REWIDTH_KEEP )); then keep_off=$SN_OFF; REWIDTH_KEEP=0; fi
  SN_TOP=$top; SN_BOTTOM=$bottom; SN_BODY=$body; SN_OFF=0

  printf '\e[2J'
  draw_header "$id" "$total" 1 "$total"

  local i
  if (( total <= body )); then
    # -- fits on screen: centre both ways, then hold ------------------------
    local vpad=0
    if (( CENTRE )); then vpad=$(( (body - total) / 2 )); fi
    for (( i = 0; i < total; i++ )); do
      draw_line "$(( top + vpad + i ))" "${NFO_LINES[i]}"
    done
    local secs=$(( SHORT_MIN + (SHORT_MAX - SHORT_MIN) * total / body ))
    if (( secs > SHORT_MAX )); then secs=$SHORT_MAX; fi
    # Arrows and stray ESC restart the hold rather than advancing: nothing to
    # scroll here, and a mistimed keypress should not skip the slide.
    while :; do
      if (( PAUSED )); then
        draw_status "PAUSED  ·  space: resume  ·  ←→ history  ·  q: quit"
        wait_key "$PAUSE_WAIT"
      else
        draw_status "holding ${secs}s  ·  space: pause  ·  ←→ history  ·  q: quit"
        wait_key "$secs"
      fi
      case $KEY_ACTION in
        pause) PAUSED=$(( ! PAUSED )) ;;
        wrapmode)  HYBRID_WRAP=$(( ! HYBRID_WRAP ))
                   if rewidth 0; then KEY_ACTION="rewidth"; return; fi ;;
        palette)   VGA_PALETTE=$(( ! VGA_PALETTE ))
                   if rewidth 0; then KEY_ACTION="rewidth"; return; fi ;;
        narrower)  if rewidth -1; then KEY_ACTION="rewidth"; return; fi ;;
        wider)     if rewidth  1; then KEY_ACTION="rewidth"; return; fi ;;
        narrower8) if rewidth -8; then KEY_ACTION="rewidth"; return; fi ;;
        wider8)    if rewidth  8; then KEY_ACTION="rewidth"; return; fi ;;
        up|down|pgup|pgdn|home|end|none) continue ;;
        timeout) if (( PAUSED )); then continue; fi; return ;;
        *) return ;;
      esac
    done
  fi

  # -- taller than the screen: scroll ---------------------------------------
  #
  # At the requested 1-2 s/line a 400-line file would run 8 minutes, so the
  # delay is compressed to fit MAX_SLIDE_SECONDS. The whole file is still
  # shown; it just moves faster when it has to.
  local maxoff=$(( total - body ))
  if (( keep_off > maxoff )); then keep_off=$maxoff; fi
  if (( keep_off > 0 )); then SN_OFF=$keep_off; fi
  local delay
  delay=$(awk -v d="$SCROLL_DELAY" -v n="$maxoff" -v cap="$MAX_SLIDE_SECONDS" \
    'BEGIN { t = d * n; if (t > cap && n > 0) d = cap / n; if (d < 0.03) d = 0.03
             printf "%.4f", d }')

  # How many idle ticks to linger at the end before moving on. Recomputed from
  # the delay so a fast scroll does not blow past the last screen.
  local end_needed
  end_needed=$(awk -v h="$END_HOLD" -v d="$delay" \
    'BEGIN { n = int(h / d + 0.999); if (n < 1) n = 1; print n }')
  local end_ticks=0

  # Manual scrolling suspends the auto-advance for SCROLL_GRACE seconds,
  # expressed in ticks of the current delay so no clock call is needed in the
  # hot loop. Space sets PAUSED, which is indefinite and survives the slide.
  local grace_needed grace=0
  grace_needed=$(awk -v g="$SCROLL_GRACE" -v d="$delay" \
    'BEGIN { n = int(g / d + 0.999); if (n < 1) n = 1; print n }')

  # DECSTBM: confine scrolling to the body so the header stays pinned.
  printf '\e[%d;%dr' "$top" "$bottom"
  redraw_body

  while :; do
    draw_header "$id" "$total" "$(( SN_OFF + body ))" "$total"

    local where
    where=$(printf 'lines %d-%d/%d' "$(( SN_OFF + 1 ))" "$(( SN_OFF + body ))" "$total")
    if (( PAUSED )); then
      draw_status "${where}  ·  PAUSED  ·  space: resume  ·  ↑↓ ←→  ·  q: quit"
      wait_key "$PAUSE_WAIT"
    elif (( grace > 0 )); then
      draw_status "${where}  ·  manual, resuming in ~$(awk -v n="$grace" -v d="$delay" \
        'BEGIN { printf "%.0f", n * d }')s  ·  space: hold  ·  q: quit"
      wait_key "$delay"
    elif (( SN_OFF >= maxoff )); then
      draw_status "${where}  ·  end  ·  ↑↓ ←→  ·  space: pause  ·  q: quit"
      wait_key "$delay"
    else
      draw_status "${where}  ·  ${delay}s/line  ·  ↑↓ scroll  ·  ←→ history  ·  q: quit"
      wait_key "$delay"
    fi

    # Any manual input restarts the auto-advance countdown (wait_key is called
    # fresh each pass) and clears the end-of-file linger.
    case $KEY_ACTION in
      quit|skip|prev|next) printf '\e[r'; return ;;
      wrapmode)
        HYBRID_WRAP=$(( ! HYBRID_WRAP ))
        if rewidth 0; then REWIDTH_KEEP=1; KEY_ACTION="rewidth"; printf '\e[r'; return; fi ;;
      palette)
        VGA_PALETTE=$(( ! VGA_PALETTE ))
        if rewidth 0; then REWIDTH_KEEP=1; KEY_ACTION="rewidth"; printf '\e[r'; return; fi ;;
      narrower|wider|narrower8|wider8)
        # Keep the reading position across the re-render.
        local d=1
        case $KEY_ACTION in narrower) d=-1 ;; narrower8) d=-8 ;; wider8) d=8 ;; esac
        if rewidth "$d"; then
          REWIDTH_KEEP=1; KEY_ACTION="rewidth"; printf '\e[r'; return
        fi ;;
      pause) PAUSED=$(( ! PAUSED )); grace=0; end_ticks=0 ;;
      none) end_ticks=0 ;;
      up)
        if (( SN_OFF > 0 )); then SN_OFF=$(( SN_OFF - 1 )); scroll_up_one; fi
        grace=$grace_needed; end_ticks=0 ;;
      down)
        if (( SN_OFF < maxoff )); then SN_OFF=$(( SN_OFF + 1 )); scroll_down_one; fi
        grace=$grace_needed; end_ticks=0 ;;
      pgup)
        SN_OFF=$(( SN_OFF - body )); if (( SN_OFF < 0 )); then SN_OFF=0; fi
        redraw_body; grace=$grace_needed; end_ticks=0 ;;
      pgdn)
        SN_OFF=$(( SN_OFF + body )); if (( SN_OFF > maxoff )); then SN_OFF=$maxoff; fi
        redraw_body; grace=$grace_needed; end_ticks=0 ;;
      home) SN_OFF=0; redraw_body; grace=$grace_needed; end_ticks=0 ;;
      end)  SN_OFF=$maxoff; redraw_body; grace=$grace_needed; end_ticks=0 ;;
      timeout)
        if (( PAUSED )); then continue; fi
        if (( grace > 0 )); then grace=$(( grace - 1 )); continue; fi
        if (( SN_OFF < maxoff )); then
          SN_OFF=$(( SN_OFF + 1 )); scroll_down_one; end_ticks=0
        else
          end_ticks=$(( end_ticks + 1 ))
          if (( end_ticks >= end_needed )); then printf '\e[r'; return; fi
        fi ;;
    esac
  done
}

# Progress while the network is busy.
#
# This used to be printed AFTER next_pack and load_pack had already run, i.e.
# after the two slowest steps, so a new pack showed a blank screen for several
# seconds and then flashed a message it no longer needed. Each phase now
# announces itself before it blocks.
show_loading() {
  local msg=$1 col
  col=$(( (COLS - ${#msg}) / 2 ))
  if (( col < 1 )); then col=1; fi
  printf '\e[2J\e[%d;%dH\e[2m%s\e[0m' "$(( ROWS / 2 ))" "$col" "$msg"
}

show_error() {
  local subtitle=${2:-"retrying shortly · q to quit"}
  printf '\e[2J\e[H'
  printf '\e[%d;3H\e[1m%s\e[0m' "$(( ROWS / 2 ))" "$1"
  printf '\e[%d;3H\e[2m%s\e[0m' "$(( ROWS / 2 + 1 ))" "$subtitle"
  wait_key 5
}

# There is deliberately NO background spinner here any more.
#
# An earlier version animated one in a subshell and cleanup() never killed it.
# Ctrl+C exited the parent, the EXIT trap restored the terminal, and the
# orphaned subshell carried on repainting "contacting the archive" over the
# user's shell prompt forever -- which looked exactly like a hang that Ctrl+C
# could not stop. A background process that can outlive its owner is a bug
# waiting to happen. Progress is now printed from the foreground, before the
# alternate screen is entered, where nothing can leak and Ctrl+C behaves
# completely normally.

# ===========================================================================
# PROBE MODE
# ===========================================================================
#
# The API response shape is not publicly documented, so rather than guessing a
# schema and silently producing wrong results, this prints what actually comes
# back. Use it to confirm the endpoint before trusting the pool.

probe() {
  local reached=0 pack="" file=""
  local now; now=$(date +%Y)

  printf '== GET %s/year/%s\n' "$API_URL" "$now"
  if fetch "${API_URL}/year/${now}" "$MAX_BYTES_INDEX" 1; then
    reached=1
    mapfile -t PACKS < <(printf '%s' "$FETCH_BODY" | parse_year | cut -f1)
    printf '   HTTP %s, %d packs: %s\n' "${LAST_HTTP:-?}" "${#PACKS[@]}" \
      "$(printf '%s ' ${PACKS[@]:0:6})"
    pack=${PACKS[0]:-}
  else
    printf '   FAILED: %s\n' "$(fetch_hint)"
  fi

  if [[ -n $pack ]]; then
    printf '\n== GET %s/pack/%s\n' "$API_URL" "$pack"
    if load_pack "$pack"; then
      printf '   HTTP %s, %d renderable files: %s\n' "${LAST_HTTP:-?}" \
        "${#FILES[@]}" "$(printf '%s ' ${FILES[@]:0:6})"
      file=${FILES[0]:-}
    else
      printf '   FAILED: %s\n' "$(fetch_hint)"
    fi
  fi

  # The raw path is inferred, so verify it rather than trusting the guess.
  if [[ -n $file ]]; then
    printf '\n== GET %s/pack/%s/raw/%s\n' "$BASE" "$pack" "$file"
    if fetch "${BASE}/pack/${pack}/raw/${file}"; then
      printf '   HTTP %s, %s bytes -- raw path confirmed\n' \
        "${LAST_HTTP:-?}" "${#FETCH_BODY}"
      printf '   first lines after sanitising:\n'
      to_utf8 "$FETCH_BODY" | render_ansi 80 \
        | head -6 | sed 's/^/     /'
    else
      printf '   FAILED: %s\n' "$(fetch_hint)"
      printf '   the /raw/ path guess is wrong; tell me and I will fix it\n'
    fi
  fi

  if (( ! reached )); then
    warn "the API did not respond - check connectivity, or NFO_API"
    return 1
  fi
}

# ===========================================================================
# SELF TEST
# ===========================================================================
#
# Dithering depends on three things downstream of this script: whether the
# font draws the four shade glyphs at four different densities, whether the
# terminal gives them one column or two, and whether it can do 24-bit colour.
# All three are measurable, so measure them instead of guessing.

# How many columns did the terminal actually use to draw this string? Asks
# the terminal with a cursor-position report rather than assuming.
measure_cols() {
  local str=$1 save resp c col i
  # Braces so the 2>/dev/null covers the failing redirection: redirections
  # are applied left to right, so trailing it on the exec itself is too late
  # and bash still prints "No such device".
  if ! { exec 4<>/dev/tty; } 2>/dev/null; then printf 'no tty'; return 0; fi
  save=$(stty -g <&4 2>/dev/null || true)
  stty -echo -icanon min 0 time 0 <&4 2>/dev/null || true

  printf "\r%s\033[6n" "$str" >&4
  resp=""
  for (( i = 0; i < 24; i++ )); do
    if IFS= read -rsn1 -t 0.4 -u 4 c 2>/dev/null; then
      resp+=$c
      if [[ $c == R ]]; then break; fi
    else
      break
    fi
  done
  printf "\r\033[2K" >&4

  if [[ -n $save ]]; then stty "$save" <&4 2>/dev/null || true; fi
  exec 4<&- 2>/dev/null || true

  col=${resp##*;}; col=${col%R}
  if [[ $col =~ ^[0-9]+$ ]]; then printf "%s" "$(( col - 1 ))"; else printf "?"; fi
}

selftest() {
  # Explicit UTF-8 bytes, not printf \u: that depends on the locale being
  # UTF-8, and this is exactly the situation where it might not be.
  local sh_l sh_m sh_d full up lo box
  sh_l=$(printf '\342\226\221')   # light shade
  sh_m=$(printf '\342\226\222')   # medium shade
  sh_d=$(printf '\342\226\223')   # dark shade
  full=$(printf '\342\226\210')   # full block
  up=$(printf '\342\226\200')     # upper half
  lo=$(printf '\342\226\204')     # lower half
  box=$(printf '\342\224\200')    # box drawing horizontal

  printf 'nfoslide self-test\n\n'
  printf '  TERM=%s  COLORTERM=%s  LANG=%s\n' \
    "${TERM:-unset}" "${COLORTERM:-unset}" "${LANG:-${LC_ALL:-unset}}"
  if (( VGA_PALETTE )); then
    printf '  palette: real VGA colours, 24-bit\n\n'
  else
    printf '  palette: your terminal 16 colours  (--palette vga to force VGA)\n\n'
  fi

  printf -- '-- 1. four densities?  If these bars look alike, it is your font.\n'
  local label glyph n
  for spec in "light  25:$sh_l" "medium 50:$sh_m" "dark   75:$sh_d" "full  100:$full"; do
    label=${spec%%:*}; glyph=${spec#*:}
    printf '     %s%%  ' "$label"
    for (( n = 0; n < 40; n++ )); do printf '%s' "$glyph"; done
    printf '\n'
  done

  printf '\n-- 2. a real dither ramp, cyan on blue, as art actually uses it\n     '
  if (( VGA_PALETTE )); then
    printf '\033[0;38;2;85;255;255;48;2;0;0;170m'
  else
    printf '\033[0;1;36;44m'
  fi
  for glyph in " " "$sh_l" "$sh_m" "$sh_d" "$full"; do
    for (( n = 0; n < 12; n++ )); do printf '%s' "$glyph"; done
  done
  printf '\033[0m\n'

  printf '\n-- 3. columns per glyph.  Anything but 1 breaks every piece.\n'
  for spec in "light shade:$sh_l" "medium shade:$sh_m" "full block:$full" \
              "upper half:$up" "lower half:$lo" "box drawing:$box" "plain ASCII:A"; do
    printf '     %-14s %s\n' "${spec%%:*}" "$(measure_cols "${spec#*:}")"
  done
  printf '     2 means the terminal treats East Asian ambiguous width as wide.\n'
  printf '     Turn that off, or every piece doubles in width and wraps.\n'

  printf '\n-- 4. 24-bit colour: a smooth ramp, not six bands\n     '
  for (( n = 0; n < 60; n++ )); do
    printf '\033[48;2;%d;%d;%dm ' "$(( n * 4 ))" "$(( 80 + n * 2 ))" "$(( 255 - n * 4 ))"
  done
  printf '\033[0m\n\n'
}

# ===========================================================================
# DUMP MODE
# ===========================================================================
#
# Four rendering bugs so far have been diagnosed by squinting at screenshots,
# and I guessed wrong on some of them. This prints the actual bytes of one
# file plus what the archive says about it, so the next question can be
# settled with evidence instead of inference.
#
#   ./nfoslide.sh --dump 0196ciph/LI_MP.ANS

# A column ruler: tens digit every tenth column, + every fifth.
dump_ruler() {
  local w=$1 i out=""
  for (( i = 1; i <= w; i++ )); do
    if   (( i % 10 == 0 )); then out+=$(( (i / 10) % 10 ))
    elif (( i % 5 == 0 ));  then out+="+"
    else                         out+="-"
    fi
  done
  printf '%s' "$out"
}

dump_file() {
  local spec=$1 pack file
  pack=${spec%%/*}; file=${spec#*/}
  if [[ $pack == "$spec" || -z $file ]]; then
    die "--dump takes PACK/FILE, e.g. 0196ciph/LI_MP.ANS"
  fi
  pack_is_valid "$pack" || die "bad pack name"
  file_is_valid "$file" || die "bad file name"

  printf "== %s/%s\n" "$pack" "$file"
  if load_pack "$pack"; then
    printf "   archive says: width=%s cols, artist=%s\n" \
      "${FILE_COLS[$file]:-unknown}" "${FILE_ARTIST[$file]:-unknown}"
    # Print the raw pixel width and BOTH readings. The derived number alone is
    # not enough to check my arithmetic: ansilove draws with a 9-pixel or an
    # 8-pixel font depending on the file, and when both divide exactly the
    # choice is a judgement call. Showing the inputs makes it checkable.
    if [[ -n ${FILE_ICE[$file]:-} ]]; then
      printf "   SAUCE present: icecolors=%s -> %s\n" "${FILE_ICE[$file]}" \
        "$( [[ ${FILE_ICE[$file]} == true ]] && echo "SGR 5 is a bright background" \
                                            || echo "SGR 5 is literal blink" )"
    fi
    local px=${FILE_PX[$file]:-}
    if [[ -n $px ]]; then
      local c8="-" c9="-"
      if (( px % 8 == 0 )); then c8=$(( px / 8 )); fi
      if (( px % 9 == 0 )); then c9=$(( px / 9 )); fi
      printf "   1:1 render is %s px wide  ->  /8 = %s cols,  /9 = %s cols\n" "$px" "$c8" "$c9"
      if [[ $c8 != "-" && $c9 != "-" ]]; then
        printf "   (both divide, so pixels alone cannot decide -- SAUCE does)\n"
      fi
    fi
  else
    printf "   pack listing failed: %s\n" "$(fetch_hint)"
  fi

  fetch "${BASE}/pack/${pack}/raw/${file}" || die "fetch failed: $(fetch_hint)"
  local raw=$FETCH_BODY
  printf "   %s bytes\n" "${#raw}"

  local sauce_h=""
  if [[ -n ${FILE_SAUCE_H[$file]:-} ]]; then sauce_h=${FILE_SAUCE_H[$file]}; fi

  printf "\n-- structure at several widths (rows x widest line) --\n"
  if [[ -n $sauce_h ]]; then
    printf "   SAUCE says the piece is %s rows tall\n" "$sauce_h"
  fi
  local w
  for w in 0 80 100 132 160; do
    local out rows wide
    out=$(to_utf8 "$raw" | render_ansi "$w")
    rows=$(printf "%s\n" "$out" | wc -l)
    wide=$(printf "%s\n" "$out" | visible_width)
    printf "   width %-4s -> %4s rows, widest %s\n" \
      "$( (( w == 0 )) && echo auto || echo "$w" )" "$rows" "$wide"
  done

  if [[ -n $DUMP_AT ]]; then
    # A dump of the head is no use when the trouble is at the bottom. Show a
    # window around the row in question, with a ruler so a horizontal shift
    # can be counted rather than eyeballed.
    local w=${FILE_COLS[$file]:-80} lo hi
    lo=$(( DUMP_AT - 4 )); if (( lo < 1 )); then lo=1; fi
    hi=$(( DUMP_AT + 4 ))
    printf "\n-- rendered rows %s-%s at width %s --\n" "$lo" "$hi" "$w"
    printf "        %s\n" "$(dump_ruler "$w")"
    # The ESC is built by the shell rather than written as \x1b inside the
    # sed script: GNU sed understands that escape, BSD sed does not, and a
    # sed that errors takes the whole pipeline down with it under pipefail.
    local esc; esc=$(printf '\033')
    to_utf8 "$raw" | render_ansi "$w" \
      | LC_ALL=C sed "s/${esc}\\[[0-9;]*m//g" \
      | awk -v lo="$lo" -v hi="$hi" 'NR >= lo && NR <= hi { printf "  %5d |%s|\n", NR, $0 }'

    printf "\n-- source lines %s-%s, escapes visible --\n" "$lo" "$hi"
    printf "%s" "$raw" | LC_ALL=C awk -v lo="$lo" -v hi="$hi" \
      'NR >= lo && NR <= hi { printf "  %5d  %s\n", NR, $0 }' | LC_ALL=C cat -v | cut -c1-200
  else
    printf "\n-- first 1200 bytes, escapes visible  (--at ROW for a window elsewhere) --\n"
    printf "%s" "${raw:0:1200}" | LC_ALL=C cat -v | head -30
  fi

  # 0x1A ends the art. Everything after it is SAUCE metadata and is dropped.
  # If one appears early, the tail of the picture is being silently discarded,
  # which looks exactly like "fine at the top, wrong at the bottom".
  printf "\n-- EOF marker (0x1A): everything after it is discarded --\n"
  local sub_at total_len
  total_len=${#raw}
  sub_at=$(printf '%s' "$raw" | LC_ALL=C awk '{ p = index($0, sprintf("%c", 26))
                                                if (p) { print off + p; exit } 
                                                off += length($0) + 1 }
                                              END { }')
  if [[ -n $sub_at ]]; then
    printf "   at byte %s of %s" "$sub_at" "$total_len"
    if (( total_len - sub_at > 512 )); then
      printf "   *** %s bytes of art discarded after it ***\n" "$(( total_len - sub_at - 128 ))"
    else
      printf "   (normal: just the SAUCE trailer follows)\n"
    fi
  else
    printf "   none present\n"
  fi

  printf "\n-- NUL bytes (each is a cell; losing one shears everything after) --\n"
  local nuls
  nuls=$(curl --silent --show-error --location \
              --proto '=https' --proto-redir '=https' --tlsv1.2 \
              --max-redirs "$MAX_REDIRS" \
              --connect-timeout "$CONNECT_TIMEOUT" --max-time "$MAX_TIME" \
              --max-filesize "$MAX_BYTES" --compressed --fail \
              --user-agent "$UA" -- "${BASE}/pack/${pack}/raw/${file}" 2>/dev/null \
         | LC_ALL=C tr -cd '\000' | wc -c)
  printf "   %s NUL bytes in the file, now preserved as spaces\n" "$nuls"

  printf "\n-- line-terminator census (tells us if it relies on autowrap) --\n"
  local nl cr
  nl=$(printf "%s" "$raw" | LC_ALL=C tr -cd "\n" | wc -c)
  cr=$(printf "%s" "$raw" | LC_ALL=C tr -cd "\r" | wc -c)
  printf "   LF=%s  CR=%s  (few or none => the piece relies on terminal wrapping)\n" "$nl" "$cr"
  printf "   SGR 5 (iCE bright background) used: %s times\n" \
    "$(printf "%s" "$raw" | LC_ALL=C awk -v E="$(printf "\033")" '
        { n = split($0, P, E "\\[")
          for (i = 2; i <= n; i++) {
            if (P[i] !~ /^[0-9;]*m/) continue
            sub(/m.*/, "", P[i])
            k = split(P[i], Q, ";")
            for (j = 1; j <= k; j++) if (Q[j] + 0 == 5 && Q[j] != "") c++
          }
        } END { print c + 0 }')"
}

# ===========================================================================
# DIAGNOSE MODE
# ===========================================================================
#
# --fail hides the error body, which is exactly the thing that identifies WHY
# a 403 happened: a WAF challenge page, an origin denial, and a corporate
# proxy interstitial all look identical without it. This drops --fail and
# prints headers plus the first part of the body.
#
# The body is still untrusted remote content, so it goes through the same
# sanitiser as everything else before it touches the terminal.

# Compact version of diagnose(), run automatically when discovery fails.
auto_diagnose() {
  printf '\n[1] control: a site that is NOT %s\n' "$HOST"
  raw_request "https://example.com/" "https://example.com/" -o /dev/null
  printf '\n[2] target: %s root, headers AND body\n' "$HOST"
  raw_request "${BASE}/" "${BASE}/"
  printf '\n[3] verdict\n'
  printf '    If [1] also failed  -> the block is your network/proxy/VPN, not the site.\n'
  printf '    Server: cloudflare  -> bot protection; ask the maintainers, do not evade.\n'
  printf '    Origin 403 body     -> a UA or path rule; try NFO_UA="your@email".\n'
}

raw_request() {
  local label=$1 url=$2; shift 2
  printf '\n--- %s\n    %s\n' "$label" "$url"
  LC_ALL=C curl --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --max-redirs 3 --connect-timeout 6 --max-time 20 \
    --max-filesize 262144 \
    -D - "$@" -- "$url" 2>&1 \
    | LC_ALL=C sed -n '1,45p' \
    | sanitise_stream \
    | LC_ALL=C cut -c1-160 \
    | sed 's/^/    /'
}

diagnose() {
  local chrome='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36'

  printf '== connectivity control (NOT %s) ==\n' "$HOST"
  printf '   if this also fails, the block is your network or proxy, not the site.\n'
  raw_request "example.com" "https://example.com/" -o /dev/null

  printf '\n== %s, this script as-is ==\n' "$HOST"
  raw_request "site root" "${BASE}/"                       -A "$UA"
  raw_request "api year"  "${API_URL}/year/$(date +%Y)"     -A "$UA"

  printf '\n== same paths, browser User-Agent ==\n'
  printf '   a DIFFERENT result here means the block keys on User-Agent.\n'
  raw_request "api (browser UA)" "${API_URL}/year/$(date +%Y)" -A "$chrome" \
      -H 'Accept: text/html,application/xhtml+xml,*/*;q=0.8' \
      -H 'Accept-Language: en-US,en;q=0.9'


  printf '\n== how to read this ==\n'
  cat <<'READ'
    Server: cloudflare  +  cf-ray / cf-mitigated: challenge
        -> a bot-protection challenge. Header tweaks will not fix it; the
           block is on TLS fingerprint and JS execution, not on what you send.
           Do not route around it. Ask the maintainers instead (they publish
           contact details on github.com/Defacto2) or use the SQL dump.

    403 with a short origin body, browser UA succeeds
        -> a plain User-Agent rule. Set NFO_UA to something identifying you.

    403 on example.com too
        -> the block is on YOUR side, not the archive. Look for a giveaway
           header: x-deny-reason, Via:, X-Squid-Error, X-Forefront-*, or a
           content-type of text/plain with a one-line explanation. Egress
           allowlists (corporate proxies, container sandboxes, some VPNs)
           return exactly this shape. Fix it there, not in this script.

    404 on the api but 200 on /
        -> wrong path. The API is on the api. subdomain, not /api. Point
           NFO_API at the right base.
READ
}

# ===========================================================================
# MAIN
# ===========================================================================

main() {
  if (( SELFTEST )); then selftest; exit 0; fi
  if (( DIAGNOSE )); then PROGRESS=0; diagnose; exit 0; fi
  if [[ -n $DUMP_SPEC ]]; then PROGRESS=0; dump_file "$DUMP_SPEC"; exit $?; fi
  # Seed once in the parent. Bash seeds RANDOM itself, but being explicit
  # documents that the sequence lives here and not in a subshell.
  RANDOM=$(( ($(date +%s) ^ $$) & 32767 ))

  if (( PROBE )); then probe; exit $?; fi

  # Discovery happens on the NORMAL screen, before term_init. It is the slow,
  # failure-prone part, so the user gets to watch it, read any error, and hit
  # Ctrl+C with completely ordinary semantics. Hiding this behind an alternate
  # screen was what made a slow failure look like a freeze.
  printf 'nfoslide: building pack list from %s (Ctrl+C to abort)\n' "$HOST" >&2
  local ok=0
  if build_pool; then ok=1; fi

  if (( ! ok )); then
    warn "no packs discovered — $(fetch_hint)"
    # Diagnose automatically instead of asking the user to run another
    # command. --fail hides the error body, and that body is the only thing
    # that distinguishes a WAF challenge from an egress allowlist.
    printf '\n=== automatic diagnosis (re-requesting without --fail) ===\n' >&2
    auto_diagnose >&2
    die "see the diagnosis above; --diagnose gives the full version"
  fi
  printf 'nfoslide: %d packs from %s\n' "${#PACKS[@]}" "$YEAR" >&2

  PROGRESS=0          # from here on the alt screen owns the terminal
  term_init

  local consecutive_failures=0 pack="" file="" left=0 tries mode="new"

  # Fetch one new artwork into NFO_LINES/CUR_META and push it onto history.
  # Returns non-zero if nothing usable came back, so the caller can retry.
  fetch_next() {
    if (( left <= 0 )) || [[ -z $pack ]]; then
      show_loading "picking a pack from the archive ..."
      if ! next_pack; then
        ERRORS=$(( ERRORS + 1 ))
        show_error "could not reach the API"
        return 1
      fi
      pack=$PICKED
      show_loading "listing ${pack} ..."
      if ! load_pack "$pack"; then
        SKIPPED=$(( SKIPPED + 1 ))
        consecutive_failures=$(( consecutive_failures + 1 ))
        pack=""
        return 1
      fi
      left=$FILES_PER_PACK
    fi

    # Prefer something not shown yet; give up after a few draws rather than
    # spinning once a pack is exhausted.
    file=""
    for (( tries = 0; tries < 12; tries++ )); do
      if ! pick_into ${FILES[@]+"${FILES[@]}"}; then break; fi
      if [[ -z ${SEEN[${pack}/${PICKED}]:-} ]]; then file=$PICKED; break; fi
    done
    # Every file in this pack has already been shown. Count it as a failure
    # so the guard below can trip: otherwise the loop spins pack-after-pack
    # with no display and no chance to press a key.
    if [[ -z $file ]]; then
      left=0; pack=""
      consecutive_failures=$(( consecutive_failures + 1 ))
      return 1
    fi
    # SEEN is the only structure with no natural bound. After this many
    # artworks a session has long since stopped repeating by accident, so
    # start over rather than grow for the lifetime of the process.
    if (( ${#SEEN[@]} > SEEN_MAX )); then SEEN=(); fi
    SEEN[${pack}/${file}]=1
    left=$(( left - 1 ))

    show_loading "fetching ${pack}/${file} ..."
    if ! load_nfo "$pack" "$file"; then
      SKIPPED=$(( SKIPPED + 1 ))
      consecutive_failures=$(( consecutive_failures + 1 ))
      return 1
    fi
    consecutive_failures=0
    SHOWN=$(( SHOWN + 1 ))

    CUR_META=""
    if [[ -n ${FILE_ARTIST[$file]:-} ]]; then CUR_META="${FILE_ARTIST[$file]}"; fi
    if [[ -n ${PACK_GROUP[$pack]:-} ]]; then
      if [[ -n $CUR_META ]]; then CUR_META+="  ·  "; fi
      CUR_META+="${PACK_GROUP[$pack]}"
    fi
    if [[ -n $YEAR ]]; then CUR_META+="  ·  ${YEAR}"; fi

    hist_push "${pack}/${file}" "$CUR_META" \
              "$(printf '%s\n' ${NFO_LINES[@]+"${NFO_LINES[@]}"})" "$NFO_WIDTH"
    return 0
  }

  while :; do
    term_size

    if [[ $mode == same ]]; then
      :                       # NFO_LINES already holds the re-rendered art
    elif [[ $mode == hist ]]; then
      hist_load "$HIST_POS"
    else
      if ! fetch_next; then
        if (( consecutive_failures >= 8 )); then
          ERRORS=$(( ERRORS + 1 )); consecutive_failures=0
          show_error "8 fetches in a row failed - network trouble?"
          if [[ $KEY_ACTION == quit ]]; then break; fi
        fi
        # Stay responsive: without this, a run of failures locks the user out
        # of quitting because nothing between here and the next fetch reads
        # the keyboard.
        wait_key 0.05
        if [[ $KEY_ACTION == quit ]]; then break; fi
        continue
      fi
    fi

    if hist_is_live; then
      HIST_LABEL=""
    else
      HIST_LABEL="$(printf '◀ %d/%d  ·  ' "$(( HIST_POS + 1 ))" "${#HIST_KEY[@]}")"
    fi

    show_nfo "${HIST_KEY[HIST_POS]}"
    if [[ $KEY_ACTION == quit ]]; then break; fi

    case $KEY_ACTION in
      rewidth)
        # Same artwork, new canvas. Do not reload from history: NFO_LINES has
        # already been replaced and the history entry updated in place.
        mode="same" ;;
      prev)
        # Older. Already at the oldest kept artwork: just redisplay it.
        if (( HIST_POS > 0 )); then HIST_POS=$(( HIST_POS - 1 )); fi
        mode="hist" ;;
      *)
        # Newer, for right-arrow, any-key, and the auto-advance alike. Only
        # fetch when there is nothing newer already in the cache.
        if (( HIST_POS < ${#HIST_KEY[@]} - 1 )); then
          HIST_POS=$(( HIST_POS + 1 )); mode="hist"
        else
          mode="new"
        fi ;;
    esac

    transition
    if [[ $KEY_ACTION == quit ]]; then break; fi
  done
}

(( ${NFOSLIDE_LIB:-0} )) || main "$@"