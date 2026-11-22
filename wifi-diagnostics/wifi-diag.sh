#!/usr/bin/env bash
# =============================================================================
#  wifi-diag.sh - read-only Wi-Fi & home-network diagnostic for Linux
#  Written for Fedora (NetworkManager + iw); also works on Ubuntu/Debian/Arch.
#
#  SAFE BY DESIGN - this script only READS and MEASURES. It does NOT:
#    * change any router, NetworkManager or system setting
#    * log in to the router or try any password
#    * disconnect any device, restart Wi-Fi, or need sudo
#
#  Usage:  bash wifi-diag.sh [--plan MBPS] [--no-speedtest] [--quick]
#    --plan MBPS      your internet plan's download speed, e.g. --plan 100
#    --no-speedtest   skip the speed / bufferbloat test (it uses ~140 MB of data)
#    --quick          shorter measurements (~2 min instead of ~5 min)
#
#  Output: printed on screen and saved as ./wifi-report-YYYYMMDD-HHMM.txt
#  Optional extras on Fedora (more detail):  sudo dnf install iw nmap mtr
# =============================================================================

set -u
export LC_ALL=C

SPEEDTEST=1; QUICK=0; PLAN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-speedtest) SPEEDTEST=0 ;;
    --quick)        QUICK=1 ;;
    --plan)         PLAN="${2:-}"; shift ;;
    -h|--help)      sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1  (see --help)"; exit 1 ;;
  esac
  shift
done
if [ -n "$PLAN" ] && ! [[ $PLAN =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "--plan needs a number in Mbit/s, e.g. --plan 100"; exit 1
fi

if [ "$QUICK" -eq 1 ]; then NPING=40; NSAMP=6; WIN=5; MTRC=10; else NPING=100; NSAMP=15; WIN=10; MTRC=20; fi

REPORT="wifi-report-$(date +%Y%m%d-%H%M).txt"
TMP=$(mktemp -d) || exit 1
trap 'rm -rf "$TMP"' EXIT
exec > >(tee "$REPORT") 2>&1
START_TS=$(date +%s)

# ----------------------------------------------------------------- helpers ---
have()    { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n\n################ %s ################\n' "$*"; }
sub()     { printf '\n--- %s ---\n' "$*"; }
show()    { printf '$ %s\n' "$*"; "$@" 2>&1 | sed 's/^/    /'; }
calc()    { awk "BEGIN{ printf \"%.1f\", $* }" 2>/dev/null; }
gt()      { [ -n "${1:-}" ] && [ -n "${2:-}" ] && awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 > b+0)}'; }
lt()      { [ -n "${1:-}" ] && [ -n "${2:-}" ] && awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0 < b+0)}'; }
isnum()   { [[ ${1:-} =~ ^-?[0-9]+([.][0-9]+)?$ ]]; }
mask_ip() { awk -F. 'NF==4{print $1"."$2".x.x"; next} {print "(hidden)"}' <<<"${1:-}"; }
is_private_ip() { [[ ${1:-} =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.) ]]; }
is_cgnat_ip()   { [[ ${1:-} =~ ^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\. ]]; }
val()     { sed -n "s/^##$1=//p" "$2" 2>/dev/null | head -1; }

FINDINGS=()
# finding <1=HIGH|2=MEDIUM|3=LOW> <CONFIRMED|POSSIBLE> <PERF|STABILITY|SECURITY> <text>
finding() { local t=2 c=1; [ "$2" = CONFIRMED ] && t=1; [ "$3" = SECURITY ] && c=2; FINDINGS+=("$1|$t|$c|$2|$3|$4"); }

sig_label() {
  local s=${1%.*}
  if   [ "$s" -ge -55 ]; then echo "excellent"
  elif [ "$s" -ge -67 ]; then echo "good"
  elif [ "$s" -ge -72 ]; then echo "fair - speed starts to drop"
  elif [ "$s" -ge -80 ]; then echo "weak - slow and unstable"
  else echo "very weak"; fi
}

OUIFILE=""
for f in /usr/share/nmap/nmap-mac-prefixes /usr/share/hwdata/oui.txt /usr/share/ieee-data/oui.txt /usr/share/misc/oui.txt; do
  [ -r "$f" ] && { OUIFILE=$f; break; }
done
oui() {
  local p; p=$(tr -d ':-' <<<"$1" | cut -c1-6 | tr 'a-f' 'A-F')
  [ -z "$OUIFILE" ] && return 0
  case "$OUIFILE" in
    *nmap-mac-prefixes) awk -v p="$p" '$1==p{$1=""; sub(/^ /,""); print; exit}' "$OUIFILE" ;;
    *) awk -v p="${p:0:2}-${p:2:2}-${p:4:2}" '$1==p && $2=="(hex)"{$1=""; $2=""; sub(/^ +/,""); print; exit}' "$OUIFILE" ;;
  esac | cut -c1-30
}
is_random_mac() { case "$(cut -c2 <<<"$1" | tr 'a-f' 'A-F')" in 2|6|A|E) return 0 ;; esac; return 1; }

echo "Wi-Fi / home network diagnostic report - $(date '+%Y-%m-%d %H:%M %Z')"
echo "Read-only: nothing was changed. No passwords collected. Public IP addresses are masked."
echo "Tip: pause big downloads/streaming on this computer while the test runs."

# ==================================================================== 1 ===
section "1. SYSTEM & TOOLS"
grep -m1 '^PRETTY_NAME=' /etc/os-release 2>/dev/null | cut -d= -f2- | tr -d '"'
echo "Kernel: $(uname -r)"
have nmcli && echo "NetworkManager: $(nmcli --version 2>/dev/null | awk '{print $NF}')"
for t in ip iw nmcli ping tracepath mtr nmap curl python3 journalctl resolvectl avahi-resolve; do
  printf '  %-14s %s\n' "$t" "$(have "$t" && echo ok || echo 'not installed')"
done
echo "  MAC vendor database: ${OUIFILE:-not found (install hwdata or nmap)}"
[ "$(id -u)" -eq 0 ] && echo "NOTE: running as root is not needed."
have iw     || echo "TIP: 'sudo dnf install iw' adds signal dBm, bitrate, retries and router radio details."
have ping   || echo "WARNING: ping is missing - latency tests will be skipped."

# ==================================================================== 2 ===
section "2. CONNECTION & IP CONFIGURATION"
ROUTE=$(ip -4 route get 1.1.1.1 2>/dev/null | head -1)
IF=$(awk   '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' <<<"$ROUTE")
GW=$(awk   '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' <<<"$ROUTE")
MYIP=$(awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' <<<"$ROUTE")
CIDR=$(ip -o -4 addr show dev "${IF:-lo}" 2>/dev/null | awk '{print $4; exit}')
PREFIX=${CIDR#*/}; isnum "$PREFIX" || PREFIX=24
MYMAC=$(cat "/sys/class/net/${IF:-lo}/address" 2>/dev/null)

# All Wi-Fi adapters on this computer (a laptop may have a built-in card AND a USB dongle)
WIFI_LIST=""
have iw    && WIFI_LIST+=" $(iw dev 2>/dev/null | awk '/Interface/{print $2}')"
have nmcli && WIFI_LIST+=" $(nmcli -t -f DEVICE,TYPE dev 2>/dev/null | awk -F: '$2=="wifi"{print $1}')"
for d in /sys/class/net/*; do
  if [ -e "$d/phy80211" ] || [ -d "$d/wireless" ]; then WIFI_LIST+=" $(basename "$d")"; fi
done
WIFI_LIST=$(tr ' ' '\n' <<<"$WIFI_LIST" | grep -v -e '^$' -e '^p2p-' | sort -u | tr '\n' ' ')
wifi_connected() {
  { have iw && iw dev "$1" link 2>/dev/null | grep -q '^Connected to'; } ||
  { have nmcli && nmcli -t -f DEVICE,STATE dev 2>/dev/null | grep -q "^$1:connected"; }
}
# Choose: 1) the adapter carrying the internet route, 2) a connected adapter, 3) the first one
WIFI_IF=""
for w in $WIFI_LIST; do [ "$w" = "${IF:-}" ] && WIFI_IF=$w; done
if [ -z "$WIFI_IF" ]; then for w in $WIFI_LIST; do wifi_connected "$w" && { WIFI_IF=$w; break; }; done; fi
[ -z "$WIFI_IF" ] && WIFI_IF=$(awk '{print $1}' <<<"$WIFI_LIST")

echo "Internet goes out via : ${IF:-NONE}"
echo "Router (gateway)      : ${GW:-NONE}"
echo "This computer         : ${MYIP:-?}/${PREFIX}   MAC ${MYMAC:-?}"
echo "Wi-Fi adapters found  : ${WIFI_LIST:-none}"
echo "Wi-Fi adapter analysed: ${WIFI_IF:-none found}"
[ -z "$GW" ] && echo "ERROR: no default gateway - the computer seems to be offline. Results will be limited."
if [ -n "$WIFI_IF" ] && [ -n "$IF" ] && [ "$IF" != "$WIFI_IF" ]; then
  echo "NOTE: traffic currently uses $IF (not Wi-Fi). Wi-Fi sections describe the Wi-Fi link only."
fi

sub "Addresses & routes"
show ip -br addr
show ip route
show ip -6 route show default

sub "DNS servers this computer uses"
SYSDNS=""
if have resolvectl && resolvectl status >/dev/null 2>&1; then
  show resolvectl dns
  SYSDNS=$(resolvectl dns "${IF:-lo}" 2>/dev/null | sed 's/^[^)]*): *//' | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$')
fi
[ -z "$SYSDNS" ] && SYSDNS=$(awk '/^nameserver/{print $2}' /etc/resolv.conf 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$' | grep -v '^127\.')
[ -z "$(resolvectl dns 2>/dev/null)" ] && show cat /etc/resolv.conf
echo "DNS servers (IPv4) used by this computer: $(echo $SYSDNS)"

CON=""
if have nmcli && [ -n "$IF" ]; then
  sub "DHCP lease received from the router"
  nmcli -f DHCP4 dev show "$IF" 2>/dev/null | grep -E 'dhcp_lease_time|domain_name_servers|routers|subnet_mask|dhcp_server_identifier|domain_name |ip_address' | sed 's/^/    /'
  LEASE=$(nmcli -f DHCP4 dev show "$IF" 2>/dev/null | sed -n 's/.*dhcp_lease_time = \([0-9]*\).*/\1/p' | head -1)
  CON=$(nmcli -g GENERAL.CONNECTION dev show "$IF" 2>/dev/null)
  if [ -n "$CON" ]; then
    sub "Settings of the active connection profile \"$CON\" (passwords are never shown)"
    nmcli connection show "$CON" 2>/dev/null | grep -E '^(connection\.type|802-11-wireless\.(ssid|band|channel|bssid|powersave|cloned-mac-address|mtu)|802-11-wireless-security\.(key-mgmt|pmf)|ipv4\.(method|dns|ignore-auto-dns)|ipv6\.(method|ip6-privacy)|802-3-ethernet\.mtu):' | sed 's/^/    /'
    BANDLOCK=$(nmcli -g 802-11-wireless.band connection show "$CON" 2>/dev/null)
    [ "$BANDLOCK" = "bg" ] && finding 2 CONFIRMED PERF "The Wi-Fi profile \"$CON\" is locked to 2.4 GHz (802-11-wireless.band=bg). 2.4 GHz is slower and more crowded than 5 GHz."
    BSSIDLOCK=$(nmcli -g 802-11-wireless.bssid connection show "$CON" 2>/dev/null)
    [ -n "$BSSIDLOCK" ] && finding 3 POSSIBLE PERF "The Wi-Fi profile is pinned to one access point (BSSID $BSSIDLOCK). This blocks roaming to a closer or less busy radio."
  fi
  if isnum "${LEASE:-}" && [ "$LEASE" -lt 1800 ]; then
    finding 3 POSSIBLE STABILITY "DHCP lease time is very short (${LEASE}s). Devices renew their address very often. 12-24 h is typical."
  fi
fi

# ==================================================================== 3 ===
section "3. WI-FI LINK QUALITY (this computer <-> router)"
SIGNAL=""; SIG_APPROX=0; FREQ=""; TXRATE=""; RXRATE=""; SSID=""; BSSID=""; CHAN=""; WIDTH=""; BAND=""; PS=""; SAVG=""
if [ -z "$WIFI_IF" ]; then
  echo "No Wi-Fi interface found on this computer - skipping Wi-Fi link checks."
elif have iw; then
  LINK=$(iw dev "$WIFI_IF" link 2>&1)
  echo "\$ iw dev $WIFI_IF link"; sed 's/^/    /' <<<"$LINK"
  if grep -q '^Connected to' <<<"$LINK"; then
    BSSID=$(awk '/^Connected to/{print $3; exit}' <<<"$LINK")
    SSID=$(sed -n 's/^[[:space:]]*SSID: //p' <<<"$LINK" | head -1)
    FREQ=$(awk '/freq:/{print int($2); exit}' <<<"$LINK")
    SIGNAL=$(awk '/signal:/{print $2; exit}' <<<"$LINK")
    RXRATE=$(awk '/rx bitrate:/{print $3; exit}' <<<"$LINK")
    TXRATE=$(awk '/tx bitrate:/{print $3; exit}' <<<"$LINK")
  fi
  INFO=$(iw dev "$WIFI_IF" info 2>&1)
  echo "\$ iw dev $WIFI_IF info"; sed 's/^/    /' <<<"$INFO"
  CHAN=$(awk '$1=="channel"{print $2; exit}' <<<"$INFO")
  WIDTH=$(sed -n 's/.*width: \([0-9]*\) MHz.*/\1/p' <<<"$INFO" | head -1)
  PS=$(iw dev "$WIFI_IF" get power_save 2>/dev/null | awk '{print $NF}')
  echo "Power saving on this Wi-Fi adapter: ${PS:-unknown}"
  show iw reg get
  REG=$(iw reg get 2>/dev/null | awk '/^country/{print $2; exit}' | tr -d ':')
  STA=$(iw dev "$WIFI_IF" station dump 2>&1)
  echo "\$ iw dev $WIFI_IF station dump"; sed 's/^/    /' <<<"$STA"
  TXPK=$(awk '/tx packets:/{print $3; exit}'    <<<"$STA")
  TXRETRY=$(awk '/tx retries:/{print $3; exit}' <<<"$STA")
  TXFAIL=$(awk '/tx failed:/{print $3; exit}'   <<<"$STA")
  BLOSS=$(awk '/beacon loss:/{print $3; exit}'  <<<"$STA")
  sub "Wi-Fi adapters in this computer (each one checked separately)"
  BEST_OTHER=""
  for w in $WIFI_LIST; do
    phy=$(iw dev "$w" info 2>/dev/null | awk '$1=="wiphy"{print "phy"$2; exit}')
    P=$( [ -n "$phy" ] && iw phy "$phy" info 2>/dev/null )
    # Fallback: with a single adapter, the combined 'iw phy' output belongs to it
    [ -z "$P" ] && [ "$(wc -w <<<"$WIFI_LIST")" -eq 1 ] && P=$(iw phy 2>/dev/null)
    bands=$(awk '/^[[:space:]]*Band [0-9]+:/{b=$2; sub(":","",b); if(b==1)print "2.4GHz"; else if(b==2)print "5GHz"; else if(b==4)print "6GHz"}' <<<"$P" | sort -u | tr '\n' ' ')
    if   grep -q 'EHT' <<<"$P"; then gen="Wi-Fi 7"
    elif grep -q 'HE Iftypes\|HE MAC Capabilities' <<<"$P"; then gen="Wi-Fi 6/6E"
    elif grep -q 'VHT Capabilities' <<<"$P"; then gen="Wi-Fi 5"
    elif grep -q 'HT20/HT40\|HT Capabilities' <<<"$P"; then gen="Wi-Fi 4"
    else gen="unknown"; fi
    drv=$(basename "$(readlink -f "/sys/class/net/$w/device/driver" 2>/dev/null)" 2>/dev/null)
    model=$(udevadm info -q property -p "/sys/class/net/$w" 2>/dev/null | sed -n 's/^ID_MODEL_FROM_DATABASE=//p' | head -1)
    bus=$(udevadm info -q property -p "/sys/class/net/$w" 2>/dev/null | sed -n 's/^ID_BUS=//p' | head -1)
    state="not connected"; wifi_connected "$w" && state="CONNECTED"
    printf '    %-14s %-11s %-16s %-10s driver=%-10s bus=%-4s %s\n' "$w" "$gen" "${bands:-?}" "$state" "${drv:-?}" "${bus:-?}" "${model:-}"
    if [ "$w" = "$WIFI_IF" ]; then ADAPT_BANDS=$bands; ADAPT_GEN=$gen; DRV=$drv
    elif grep -q '5GHz' <<<"$bands"; then BEST_OTHER="$w (${model:-$gen}, $bands)"; fi
  done
  if [ -n "${ADAPT_BANDS:-}" ] && ! grep -q '5GHz' <<<"$ADAPT_BANDS"; then
    if [ -n "$BEST_OTHER" ]; then
      finding 1 CONFIRMED PERF "This computer uses Wi-Fi adapter $WIFI_IF, which supports only 2.4 GHz, although adapter $BEST_OTHER can use 5 GHz. Connect through the better adapter."
    else
      finding 2 CONFIRMED PERF "This computer's Wi-Fi adapter ($WIFI_IF) supports only 2.4 GHz. It cannot use the faster 5 GHz band."
    fi
    echo "    NOTE: $WIFI_IF cannot see 5 GHz networks, so the 5 GHz part of the scan below will be empty."
  fi
else
  # Fallback without iw: NetworkManager + /proc/net/wireless
  ROW=$(nmcli -t -e no -f IN-USE,CHAN,FREQ,SIGNAL,SECURITY,BSSID,SSID dev wifi list ifname "$WIFI_IF" --rescan no 2>/dev/null | grep '^\*' | head -1)
  if [ -n "$ROW" ]; then
    CHAN=$(cut -d: -f2 <<<"$ROW"); FREQ=$(cut -d: -f3 <<<"$ROW" | awk '{print int($1)}')
    PCT=$(cut -d: -f4 <<<"$ROW"); BSSID=$(cut -d: -f6-11 <<<"$ROW"); SSID=$(cut -d: -f12- <<<"$ROW")
    SIGNAL=$(awk -v i="$WIFI_IF:" '$1==i{gsub(/\./,"",$4); print $4}' /proc/net/wireless 2>/dev/null)
    if ! isnum "$SIGNAL" || [ "${SIGNAL:-0}" -ge 0 ]; then SIGNAL=$(awk -v p="$PCT" 'BEGIN{printf "%d", -40-(100-p)*0.6}'); SIG_APPROX=1; fi
    echo "nmcli: SSID \"$SSID\", channel $CHAN, signal ${PCT}%"
  fi
  echo "(install 'iw' for bitrate, channel width, retries and power-save details)"
fi

if isnum "$FREQ"; then
  if   [ "$FREQ" -lt 3000 ]; then BAND="2.4"
  elif [ "$FREQ" -lt 5925 ]; then BAND="5"
  else BAND="6"; fi
fi

# --- signal stability sampling
SAMPLES="$TMP/samples"; : > "$SAMPLES"
if [ -n "$WIFI_IF" ] && [ -n "$SIGNAL" ] && { have iw || [ "$SIG_APPROX" -eq 0 ]; }; then
  sub "Signal stability: $NSAMP samples, one every 2 s"
  for i in $(seq 1 "$NSAMP"); do
    r=""; t=""
    if have iw; then
      l=$(iw dev "$WIFI_IF" link 2>/dev/null)
      if grep -q '^Connected to' <<<"$l"; then
        s=$(awk '/signal:/{print $2; exit}' <<<"$l"); r=$(awk '/rx bitrate:/{print $3; exit}' <<<"$l"); t=$(awk '/tx bitrate:/{print $3; exit}' <<<"$l")
      else s=LOST; fi
    else
      s=$(awk -v i="$WIFI_IF:" '$1==i{gsub(/\./,"",$4); print $4}' /proc/net/wireless 2>/dev/null)
    fi
    s=${s:-NA}
    printf '    %2d  signal %4s dBm   rx %6s   tx %6s Mbit/s\n' "$i" "$s" "${r:--}" "${t:--}"
    echo "$s ${r:-NA} ${t:-NA}" >> "$SAMPLES"
    [ "$i" -lt "$NSAMP" ] && sleep 2
  done
  read -r SMIN SMAX SAVG LOST RAVG < <(awk '
    $1!="NA" && $1!="LOST" {n++; s+=$1; if(min==""||$1<min)min=$1; if(max==""||$1>max)max=$1}
    $1=="LOST"{lost++}
    $2!="NA"{rn++; rs+=$2}
    END{printf "%s %s %s %d %s\n", (n?min:"NA"), (n?max:"NA"), (n?sprintf("%.0f",s/n):"NA"), lost, (rn?sprintf("%.0f",rs/rn):"NA")}' "$SAMPLES")
  echo "    -> min $SMIN / avg $SAVG / max $SMAX dBm, disconnected samples: $LOST, average rx rate: $RAVG Mbit/s"
  isnum "$SAVG" && SIGNAL=$SAVG
  isnum "$RAVG" && RXRATE=$RAVG
fi

sub "Wi-Fi link summary"
echo "Network: \"${SSID:-?}\"   Router radio (BSSID): ${BSSID:-?}"
echo "Band: ${BAND:-?} GHz   Channel: ${CHAN:-?}   Channel width: ${WIDTH:-?} MHz   Regulatory country: ${REG:-?}"
if isnum "$SIGNAL"; then
  echo "Signal: $SIGNAL dBm$([ $SIG_APPROX -eq 1 ] && echo ' (approx.)') -> $(sig_label "$SIGNAL")"
fi
if isnum "$RXRATE"; then
  echo "Link rate (PHY): download ${RXRATE} / upload ${TXRATE:-?} Mbit/s -> real-world maximum is about $(calc "$RXRATE*0.6") Mbit/s"
fi

# --- findings for the Wi-Fi link
if isnum "$SIGNAL"; then
  S=${SIGNAL%.*}
  if   [ "$S" -lt -75 ]; then finding 1 CONFIRMED PERF "Very weak Wi-Fi signal ($S dBm) at this computer. Expect low speed, retries and drop-outs."
  elif [ "$S" -lt -67 ]; then finding 1 CONFIRMED PERF "Weak Wi-Fi signal ($S dBm). Speed drops a lot below about -67 dBm."
  elif [ "$S" -lt -60 ]; then finding 3 POSSIBLE PERF "Fair Wi-Fi signal ($S dBm). Moving closer or removing obstacles would raise the link rate."
  fi
fi
if isnum "${SMIN:-}" && isnum "${SMAX:-}" && [ $((SMAX - SMIN)) -ge 12 ]; then
  finding 2 CONFIRMED STABILITY "Signal fluctuated by $((SMAX - SMIN)) dB in ${NSAMP} samples (${SMIN}..${SMAX} dBm). Likely interference, people or objects moving, or the router adjusting its power."
fi
if isnum "${LOST:-}" && [ "${LOST:-0}" -gt 0 ]; then
  finding 1 CONFIRMED STABILITY "The Wi-Fi link dropped during the test ($LOST of $NSAMP samples had no connection)."
fi
if isnum "$RXRATE"; then
  if [ "$BAND" = "5" ] && lt "$RXRATE" 200; then finding 2 CONFIRMED PERF "Low 5 GHz link rate (${RXRATE} Mbit/s). Caused by weak signal, narrow channel width or interference."; fi
  if [ "$BAND" = "2.4" ] && lt "$RXRATE" 72; then finding 2 CONFIRMED PERF "Low 2.4 GHz link rate (${RXRATE} Mbit/s)."; fi
fi
if [ "$BAND" = "5" ] && [ "${WIDTH:-}" = "20" ]; then
  finding 1 CONFIRMED PERF "5 GHz is running with only 20 MHz channel width. 80 MHz gives up to ~4x the speed. Check the router's 5 GHz 'Channel Width/Bandwidth' setting."
elif [ "$BAND" = "5" ] && [ "${WIDTH:-}" = "40" ]; then
  finding 2 POSSIBLE PERF "5 GHz is using 40 MHz channel width. 80 MHz roughly doubles the maximum speed, if the channel is not crowded."
fi
if isnum "${TXPK:-}" && isnum "${TXRETRY:-}" && [ "$TXPK" -gt 1000 ] && [ "$TXRETRY" -gt 0 ]; then
  RR=$(calc "$TXRETRY*100/$TXPK")
  gt "$RR" 30 && finding 1 CONFIRMED PERF "Very high Wi-Fi retransmission rate: ${RR}% of packets had to be re-sent. Strong sign of interference or weak signal."
  gt "$RR" 15 && ! gt "$RR" 30 && finding 2 CONFIRMED PERF "High Wi-Fi retransmission rate: ${RR}% of packets re-sent (interference or weak signal)."
fi
if isnum "${TXPK:-}" && isnum "${TXFAIL:-}" && [ "$TXPK" -gt 1000 ]; then
  FR=$(calc "$TXFAIL*100/$TXPK"); gt "$FR" 1 && finding 2 CONFIRMED STABILITY "${FR}% of Wi-Fi frames failed completely after all retries."
fi
isnum "${BLOSS:-}" && [ "$BLOSS" -gt 10 ] && finding 2 POSSIBLE STABILITY "This computer missed the router's beacons $BLOSS times. Can mean interference or signal drop-outs."
[ "${REG:-}" = "00" ] && finding 3 POSSIBLE PERF "Wi-Fi regulatory domain is 'world' (00). Some 5 GHz channels and transmit power may be restricted on this computer."

# ==================================================================== 4 ===
section "4. NEARBY NETWORKS & CHANNEL CONGESTION"
SCANAN="$TMP/scan_analysis"; : > "$SCANAN"
if have nmcli && [ -n "$WIFI_IF" ]; then
  nmcli dev wifi rescan ifname "$WIFI_IF" >/dev/null 2>&1 && sleep 5
  echo "\$ nmcli dev wifi list"
  nmcli -f IN-USE,BSSID,SSID,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY dev wifi list ifname "$WIFI_IF" --rescan no 2>&1 | sed 's/^/    /'
  nmcli -t -e no -f IN-USE,CHAN,FREQ,SIGNAL,SECURITY,BSSID,SSID dev wifi list ifname "$WIFI_IF" --rescan no 2>/dev/null > "$TMP/scan"
  sub "Congestion analysis"
  awk -v my="$SSID" '
    BEGIN { FS=":" }
    function blk(c) { if(c>=36&&c<=48)return "36-48"; if(c>=52&&c<=64)return "52-64(DFS)"; if(c>=100&&c<=112)return "100-112(DFS)";
                      if(c>=116&&c<=128)return "116-128(DFS)"; if(c>=132&&c<=144)return "132-144(DFS)"; if(c>=149&&c<=161)return "149-161";
                      if(c>=165&&c<=177)return "165-177"; return "other" }
    function abs(x) { return x<0?-x:x }
    {
      ch=$2+0; fr=$3+0; sig=$4+0; sec=$5
      ssid=$12; for(i=13;i<=NF;i++) ssid=ssid":"$i
      if(ssid=="") ssid="(hidden)"
      band=(fr<3000)?"2.4":((fr<5925)?"5":"6")
      n++; C[n]=ch; B[n]=band; S[n]=sig; N[n]=ssid; U[n]=($1=="*"); SEC[n]=sec
      if(U[n]) { curch=ch; curband=band; my=ssid; mysec=sec }
    }
    END {
      if(!n) { print "    No scan results."; exit }
      printf "    Your network \"%s\": %s GHz, channel %s, security: %s\n", my, curband, curch, mysec
      print  "    Radios of your network seen here (same name):"
      for(i=1;i<=n;i++) if(N[i]==my) {
        printf "      %3s GHz  ch %-3d  signal %3d%%%s\n", B[i], C[i], S[i], (U[i]?"   <- connected":"")
        if(B[i]=="5"&&S[i]>own5)own5=S[i]; if(B[i]=="2.4"&&S[i]>own24)own24=S[i]; if(B[i]=="6"&&S[i]>own6)own6=S[i]
      }
      for(i=1;i<=n;i++) if(N[i]!=my && my!="" && (index(N[i],my)==1 || index(my,N[i])==1) && length(N[i])>2) {
        printf "      similar name: \"%s\" %s GHz ch %d signal %d%% (maybe your router'"'"'s other band)\n", N[i], B[i], C[i], S[i]
        if(B[i]=="5"&&S[i]>sim5)sim5=S[i]
      }
      for(i=1;i<=n;i++) if(N[i]!=my) { t[B[i]]++; if(S[i]>=40) st[B[i]]++ }
      printf "    Other networks nearby: 2.4 GHz: %d (%d strong)   5 GHz: %d (%d strong)   6 GHz: %d\n", t["2.4"]+0, st["2.4"]+0, t["5"]+0, st["5"]+0, t["6"]+0

      line=""
      for(c=1;c<=13;c++) { sc=0; ov=0
        for(i=1;i<=n;i++) if(B[i]=="2.4" && N[i]!=my) { d=abs(C[i]-c); if(d<5) { sc+=S[i]/100*(1-d/5); if(S[i]>=40) ov++ } }
        SC[c]=sc; OV[c]=ov; line=line sprintf(" ch%d=%.1f", c, sc) }
      print  "    2.4 GHz interference score per channel (overlapping neighbours weighted by strength, lower = better):"
      print  "     " line
      best=1; if(SC[6]<SC[best])best=6; if(SC[11]<SC[best])best=11
      printf "    Least crowded of the non-overlapping channels 1/6/11: channel %d (score %.1f)\n", best, SC[best]

      for(i=1;i<=n;i++) if(B[i]=="5" && N[i]!=my) { k=blk(C[i]); bc[k]++; bs[k]+=S[i]/100; if(S[i]>=40) bst[k]++ }
      print "    5 GHz load per 80 MHz channel group (number of networks / load score):"
      split("36-48 52-64(DFS) 100-112(DFS) 116-128(DFS) 132-144(DFS) 149-161 165-177", order, " ")
      for(j=1;j<=7;j++) { k=order[j]; printf "      %-14s %2d networks  load %.1f%s\n", k, bc[k]+0, bs[k]+0, ((curband=="5" && blk(curch)==k) ? "   <- you are here" : "") }

      if(curband=="2.4") { cs=SC[curch]; co=OV[curch] }
      else if(curband=="5") { cs=bs[blk(curch)]+0; co=bst[blk(curch)]+0 }
      print "##CURBAND=" curband;  print "##CURCH=" curch
      print "##CURSCORE=" sprintf("%.2f", cs+0); print "##CURSTRONG=" co+0
      print "##BEST24=" best; print "##BEST24SCORE=" sprintf("%.2f", SC[best]+0)
      print "##OWN5=" (own5>sim5?own5:sim5)+0; print "##OWN24=" own24+0; print "##OWN6=" own6+0
      print "##T24=" t["2.4"]+0; print "##T5=" t["5"]+0
      print "##MYSEC=" mysec
    }' "$TMP/scan" > "$SCANAN"
  grep -v '^##' "$SCANAN"

  CURBAND=$(val CURBAND "$SCANAN"); CURCH=$(val CURCH "$SCANAN"); CURSCORE=$(val CURSCORE "$SCANAN")
  CURSTRONG=$(val CURSTRONG "$SCANAN"); BEST24=$(val BEST24 "$SCANAN"); BEST24SCORE=$(val BEST24SCORE "$SCANAN")
  OWN5=$(val OWN5 "$SCANAN"); T24=$(val T24 "$SCANAN"); T5=$(val T5 "$SCANAN"); MYSEC=$(val MYSEC "$SCANAN")

  if [ "$CURBAND" = "2.4" ] && isnum "$CURCH"; then
    if [ "$CURCH" != 1 ] && [ "$CURCH" != 6 ] && [ "$CURCH" != 11 ]; then
      if isnum "$CURSTRONG" && [ "$CURSTRONG" -gt 0 ]; then
        finding 2 CONFIRMED PERF "2.4 GHz channel $CURCH overlaps neighbouring networks on adjacent channels. Use 1, 6 or 11 (least crowded right now: $BEST24)."
      else
        finding 3 POSSIBLE PERF "2.4 GHz channel $CURCH is not one of the non-overlapping channels 1/6/11 (least crowded now: $BEST24)."
      fi
    fi
    if gt "$CURSCORE" "$(calc "${BEST24SCORE:-0}+0.8")"; then
      finding 2 CONFIRMED PERF "Your 2.4 GHz channel $CURCH is more crowded (score $CURSCORE) than channel $BEST24 (score $BEST24SCORE)."
    fi
    if isnum "$OWN5" && [ "$OWN5" -ge 35 ]; then
      finding 1 CONFIRMED PERF "This computer is on 2.4 GHz although your router's 5 GHz is available here (signal ${OWN5}%). 5 GHz is usually 3-10x faster at this distance."
    fi
    if [ "${WIDTH:-}" = "40" ] && isnum "$T24" && [ "$T24" -ge 5 ]; then
      finding 2 POSSIBLE PERF "2.4 GHz uses 40 MHz width while $T24 other 2.4 GHz networks are nearby. 20 MHz is usually more stable in crowded areas."
    fi
    if isnum "$OWN5" && [ "$OWN5" -eq 0 ] && grep -q '5GHz' <<<"${ADAPT_BANDS:-}"; then
      finding 2 POSSIBLE PERF "No 5 GHz radio of your router is visible here, although this computer supports 5 GHz. 5 GHz may be disabled, out of range, or the router may be 2.4 GHz only."
    fi
  fi
  if isnum "$CURSTRONG" && [ "$CURSTRONG" -ge 3 ]; then
    finding 2 CONFIRMED PERF "$CURSTRONG strong neighbouring networks share or overlap your channel ($CURBAND GHz ch $CURCH). They compete for airtime."
  fi
  case "$MYSEC" in
    *WEP*) finding 1 CONFIRMED SECURITY "Your Wi-Fi uses WEP encryption. It can be broken in minutes. Switch to WPA2-AES or WPA3." ;;
    "") [ -n "$CURBAND" ] && finding 1 CONFIRMED SECURITY "Your Wi-Fi appears to be OPEN (no password/encryption)." ;;
    *WPA1*) TKIP_FLAGGED=1; finding 2 CONFIRMED SECURITY "Your Wi-Fi allows old WPA1 (TKIP). It is insecure and limits speed to 54 Mbit/s for devices that use it. Use WPA2-AES only, or WPA2/WPA3." ;;
  esac
else
  echo "nmcli not available - skipping nearby network scan."
fi

# Details the router advertises about itself (iw scan dump: no root needed, uses cached scan)
if have iw && [ -n "$BSSID" ]; then
  iw dev "$WIFI_IF" scan dump 2>/dev/null > "$TMP/scandump"
  awk -v b="$BSSID" '/^BSS /{inb=(tolower(substr($2,1,17))==tolower(b))} inb' "$TMP/scandump" > "$TMP/mybss"
  if [ -s "$TMP/mybss" ]; then
    sub "What your router advertises on this radio (from beacon)"
    grep -E 'SSID: |freq: |Country: |station count|channel utili|admission|Group cipher|Pairwise ciphers|Authentication suites|MFP|WPS:|Setup State|AP setup locked|HT operation|VHT operation|HE Operation|EHT|\* channel width|\* secondary channel offset|\* primary channel|^[[:space:]]*(WPA|RSN):' "$TMP/mybss" | head -40 | sed 's/^/    /'
    STACOUNT=$(awk '/station count:/{print $NF; exit}' "$TMP/mybss")
    UTIL=$(sed -n 's/.*channel utili[sz]ation: \([0-9]*\)\/255.*/\1/p' "$TMP/mybss" | head -1)
    if   grep -q 'EHT' "$TMP/mybss"; then AP_GEN="Wi-Fi 7"
    elif grep -qi 'HE capabilities\|HE Operation' "$TMP/mybss"; then AP_GEN="Wi-Fi 6/6E"
    elif grep -qi 'VHT capabilities\|VHT operation' "$TMP/mybss"; then AP_GEN="Wi-Fi 5"
    elif grep -qi 'HT capabilities\|HT operation' "$TMP/mybss"; then AP_GEN="Wi-Fi 4"
    else AP_GEN="unknown"; fi
    echo "Router radio standard (this radio): $AP_GEN   This computer: ${ADAPT_GEN:-?}"
    [ "$BAND" = "2.4" ] && [ "$AP_GEN" = "Wi-Fi 4" ] && echo "    (normal: on 2.4 GHz, Wi-Fi 5 routers only offer Wi-Fi 4; Wi-Fi 6 routers show Wi-Fi 6 here)"
    isnum "${STACOUNT:-}" && echo "Devices connected to this router radio (router-reported): $STACOUNT"
    if isnum "${UTIL:-}"; then
      UP=$((UTIL * 100 / 255)); echo "Channel busy time (router-reported): ${UP}%"
      [ "$UP" -ge 70 ] && finding 1 CONFIRMED PERF "Your router reports its channel is busy ${UP}% of the time. Little airtime is left for new traffic: change channel or move devices to 5 GHz."
      [ "$UP" -ge 45 ] && [ "$UP" -lt 70 ] && finding 2 CONFIRMED PERF "Your router reports its channel is busy ${UP}% of the time (congested)."
    fi
    isnum "${STACOUNT:-}" && [ "$STACOUNT" -ge 20 ] && finding 2 POSSIBLE PERF "$STACOUNT devices are connected to this one router radio. Many devices share the same airtime."
    if grep -q 'WPS:' "$TMP/mybss"; then
      finding 2 CONFIRMED SECURITY "WPS is enabled on your router. The WPS PIN can be brute-forced on many routers. Disable WPS in the wireless settings."
    fi
    if [ -z "${TKIP_FLAGGED:-}" ] && grep -E 'Pairwise ciphers' "$TMP/mybss" | grep -q 'TKIP'; then
      finding 2 CONFIRMED SECURITY "Your router still allows TKIP encryption (WPA/WPA2 mixed). TKIP is insecure and forces slow 54 Mbit/s rates for devices that use it. Use 'WPA2-PSK AES' (or WPA2/WPA3)."
    fi
    if grep -E 'Authentication suites' "$TMP/mybss" | grep -q 'SAE'; then echo "WPA3 (SAE) is supported by the router: good."; fi
  else
    echo "(router beacon details not available from cached scan)"
  fi
  SURV=$(iw dev "$WIFI_IF" survey dump 2>/dev/null | awk '/frequency/{inuse=/in use/} inuse')
  NOISE=$(awk '/noise:/{print $2; exit}' <<<"$SURV")
  ACT=$(awk '/channel active time:/{print $4; exit}' <<<"$SURV"); BUSY=$(awk '/channel busy time:/{print $4; exit}' <<<"$SURV")
  if isnum "${NOISE:-}" && isnum "$SIGNAL"; then
    SNR=$(( ${SIGNAL%.*} - NOISE )); echo "Noise floor: $NOISE dBm  ->  SNR (signal-to-noise): $SNR dB"
    [ "$SNR" -lt 20 ] && finding 1 CONFIRMED PERF "Low signal-to-noise ratio ($SNR dB). Interference or noise is drowning the Wi-Fi signal (>25 dB is good)."
  fi
  if isnum "${ACT:-}" && isnum "${BUSY:-}" && [ "$ACT" -gt 0 ]; then echo "Channel busy measured by this computer: $((BUSY * 100 / ACT))%"; fi
fi

# ==================================================================== 5 ===
section "5. ROUTER IDENTIFICATION, SERVICES & UPnP"
UPNPDEV="$TMP/upnp_devices"; : > "$UPNPDEV"; UPNPOUT="$TMP/upnp_out"; : > "$UPNPOUT"
if [ -n "$GW" ]; then
  sub "Router web interface"
  H=$(curl -s -m 5 --noproxy '*' -I "http://$GW/" 2>/dev/null | tr -d '\r')
  if [ -n "$H" ]; then
    grep -iE '^(HTTP/|server:|location:|www-authenticate:|x-powered-by:)' <<<"$H" | sed 's/^/    /'
    TITLE=$(curl -s -m 5 --noproxy '*' -L --max-filesize 1000000 "http://$GW/" 2>/dev/null | tr -d '\r\n' | grep -io '<title>[^<]*' | head -1 | sed 's/<title>//I')
    echo "    Page title: ${TITLE:-?}"
  else
    echo "    No HTTP answer on port 80."
  fi
  # -k only to read the router's own (self-signed) certificate page header on the local network
  HS=$(curl -s -m 5 --noproxy '*' -k -I "https://$GW/" 2>/dev/null | tr -d '\r' | head -1)
  echo "    HTTPS admin page: ${HS:-not available}"
  if [ -n "$H" ] && [ -z "$HS" ] && ! grep -qi '^location: *https' <<<"$H"; then
    finding 3 POSSIBLE SECURITY "The router admin page is only available over plain HTTP. The admin password crosses the Wi-Fi unencrypted. This is common on home routers. Enable HTTPS admin if the router offers it."
  fi

  sub "Services open on the router (checked from inside your network)"
  PORTS="21 22 23 53 80 139 443 445 1900 2323 5000 5431 7547 8080 8291 8443 37215 49152 52869"
  OPEN=()
  for p in $PORTS; do timeout 1 bash -c "exec 3<>/dev/tcp/$GW/$p" 2>/dev/null && OPEN+=("$p"); done
  echo "    Open TCP ports: ${OPEN[*]:-none of the checked ports}"
  for p in ${OPEN[@]+"${OPEN[@]}"}; do
    case $p in
      21)    echo "      21   FTP (file sharing, unencrypted)"; finding 3 POSSIBLE SECURITY "FTP (port 21) is open on the router (usually USB file sharing). Disable it if you do not use it." ;;
      22)    echo "      22   SSH (remote admin)" ;;
      23|2323) echo "      $p   TELNET (unencrypted remote admin)"; finding 1 CONFIRMED SECURITY "Telnet (port $p) is open on the router. It is unencrypted and a favourite target of botnets. Disable it, or ask your ISP to." ;;
      53)    echo "      53   DNS (router answers name lookups)" ;;
      80|8080) echo "      $p   HTTP admin page" ;;
      443|8443) echo "      $p   HTTPS admin page" ;;
      139|445) echo "      $p  SMB file sharing (USB storage)" ;;
      1900|5000|5431|49152) echo "      $p UPnP service" ;;
      7547)  echo "      7547 TR-069 / CWMP (ISP remote management)" ;;
      8291)  echo "      8291 MikroTik Winbox" ;;
      37215|52869) echo "      $p  service linked to known router exploits"; finding 1 CONFIRMED SECURITY "Port $p is open on the router. It is associated with known exploited router flaws (Huawei HG532 / Realtek UPnP SDK). Update the firmware and ask your ISP whether the device is still supported." ;;
    esac
  done
  if have nmap; then
    sub "nmap scan of the router (top 1000 TCP ports, connect scan, no root)"
    nmap -Pn -sT -n --top-ports 1000 --open -T4 "$GW" 2>&1 | grep -E '^[0-9]+/tcp|Nmap done|MAC Address' | sed 's/^/    /'
  fi

  if have python3; then
    sub "UPnP discovery (router model, WAN status, port forwards opened by devices)"
    python3 -I - "$GW" "${MYIP:-0.0.0.0}" "$UPNPDEV" "${IF:-lo}" "$WIN" > "$UPNPOUT" 2>&1 <<'PY'
import socket, sys, time, re, ipaddress, urllib.request, urllib.parse, xml.etree.ElementTree as ET
gw, myip, devfile, iface, win = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], float(sys.argv[5])
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # never use a proxy for LAN devices

def lan(ip):
    try: return ipaddress.ip_address(ip).is_private
    except ValueError: return False
def get(url, data=None, headers=None):
    with opener.open(urllib.request.Request(url, data=data, headers=headers or {}), timeout=3) as r:
        return r.read(400000)
def tag(e): return e.tag.rsplit('}', 1)[-1]
def child(e, name):
    for c in e:
        if tag(c) == name: return (c.text or '').strip()
    return ''

# 1) SSDP discovery
msg = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\n'
       'MX: 2\r\nST: ssdp:all\r\n\r\n').encode()
found = {}
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    try: s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(myip))
    except OSError: pass
    s.settimeout(0.3)
    for _ in range(2):
        s.sendto(msg, ('239.255.255.250', 1900)); time.sleep(0.2)
    end = time.time() + 4
    while time.time() < end:
        try: data, addr = s.recvfrom(65535)
        except socket.timeout: continue
        h = {}
        for line in data.decode('utf-8', 'replace').split('\r\n')[1:]:
            if ':' in line:
                k, v = line.split(':', 1); h[k.strip().lower()] = v.strip()
        d = found.setdefault(addr[0], {'locs': set(), 'server': ''})
        if h.get('location'): d['locs'].add(h['location'])
        if h.get('server'): d['server'] = h['server']
except OSError as e:
    print('    SSDP discovery failed: %s' % e)

# 2) Read each device description (only from the device itself, only on the LAN)
devs, igds = [], []
def ipkey(ip):
    try: return tuple(int(x) for x in ip.split('.'))
    except ValueError: return (999,)
for ip in sorted(found, key=ipkey):
    d = found[ip]; info = {'ip': ip, 'server': d['server']}; wanconn = []; wancommon = []
    for loc in sorted(d['locs']):
        u = urllib.parse.urlparse(loc)
        if u.hostname != ip or not lan(ip): continue
        try: root = ET.fromstring(get(loc))
        except Exception: continue
        dev = next((e for e in root.iter() if tag(e) == 'device'), None)
        if dev is None: continue
        for k in ('friendlyName', 'manufacturer', 'modelName', 'modelNumber', 'modelDescription'):
            v = child(dev, k)
            if v and not info.get(k): info[k] = v
        base = next(((e.text or '').strip() for e in root.iter() if tag(e) == 'URLBase' and (e.text or '').strip()), '') or loc
        for svc in (e for e in root.iter() if tag(e) == 'service'):
            st, cu = child(svc, 'serviceType'), child(svc, 'controlURL')
            if not cu: continue
            full = urllib.parse.urljoin(base, cu)
            if urllib.parse.urlparse(full).hostname != ip: continue
            if 'WANIPConnection' in st or 'WANPPPConnection' in st: wanconn.append((full, st))
            elif 'WANCommonInterfaceConfig' in st: wancommon.append((full, st))
    devs.append(info)
    if wanconn: igds.append((ip, wanconn, wancommon, info))

print('    Devices that answered UPnP/SSDP: %d' % len(devs))
with open(devfile, 'w') as f:
    for i in devs:
        model = ' '.join(x for x in (i.get('manufacturer', ''), i.get('modelName', ''), i.get('modelNumber', '')) if x)
        print('      %-15s %s | %s | server: %s' % (i['ip'], i.get('friendlyName', '?'), model or '?', i['server'] or '?'))
        f.write('%s|%s|%s\n' % (i['ip'], i.get('friendlyName', ''), model))
        m = re.search(r'Portable SDK for UPnP devices/1\.6\.(\d+)', i['server'])
        if m and int(m.group(1)) < 18:
            print('##OLDLIBUPNP=%s %s' % (i['ip'], m.group(0)))
        if re.search(r'Linux/2\.', i['server']):
            print('##OLDKERNEL=%s' % i['ip'])

def soap(url, st, action, args=()):
    a = ''.join('<%s>%s</%s>' % (k, v, k) for k, v in args)
    body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:%s xmlns:u="%s">%s</u:%s>'
            '</s:Body></s:Envelope>') % (action, st, a, action)
    x = get(url, body.encode(), {'Content-Type': 'text/xml; charset="utf-8"', 'SOAPAction': '"%s#%s"' % (st, action)})
    return {tag(e): (e.text or '').strip() for e in ET.fromstring(x).iter() if len(e) == 0}

# 3) Internet Gateway (read-only "Get..." queries only)
if not igds:
    print('    No UPnP Internet Gateway answered (UPnP is probably disabled on the router).')
    print('##IGD=0')
else:
    ip, wanconn, wancommon, info = sorted(igds, key=lambda x: x[0] != gw)[0]
    print('##IGD=1')
    print('    UPnP Internet Gateway: %s (%s %s) - UPnP is ENABLED on the router'
          % (ip, info.get('manufacturer', ''), info.get('modelName', '')))
    url, st = wanconn[0]
    try:
        r = soap(url, st, 'GetStatusInfo')
        up = r.get('NewUptime', '')
        ok = up.isdigit() and int(up) < 5 * 365 * 86400
        print('    WAN status: %s, uptime %s s%s, last error: %s' % (r.get('NewConnectionStatus', '?'), up or '?',
              '' if ok or not up else ' (implausible value reported by the router - ignore)', r.get('NewLastConnectionError', '?')))
        print('##WANSTATUS=%s' % r.get('NewConnectionStatus', ''))
        if ok: print('##WANUPTIME=%s' % up)
    except Exception as e:
        print('    WAN status: not available (%s)' % e.__class__.__name__)
    try:
        ext = soap(url, st, 'GetExternalIPAddress').get('NewExternalIPAddress', '')
        cls = 'unknown'
        try:
            a = ipaddress.ip_address(ext)
            if a in ipaddress.ip_network('100.64.0.0/10'): cls = 'cgnat'
            elif a.is_private: cls = 'private'
            elif a.is_global: cls = 'public'
        except ValueError: pass
        masked = '.'.join(ext.split('.')[:2] + ['x', 'x']) if ext.count('.') == 3 else '?'
        desc = {'public': 'public address (normal)',
                'cgnat': 'CARRIER-GRADE NAT: your ISP shares one public IP among many customers',
                'private': 'PRIVATE address: this router sits behind another router/modem (double NAT)',
                'unknown': 'unknown'}[cls]
        print('    Router WAN IP: %s -> %s' % (masked, desc))
        print('##WANCLASS=%s' % cls); print('##WANIP=%s' % ext)
    except Exception as e:
        print('    WAN IP: not available (%s)' % e.__class__.__name__)
    if wancommon:
        url2, st2 = wancommon[0]
        try:
            r = soap(url2, st2, 'GetCommonLinkProperties')
            print('    WAN link: %s, reported max up/down: %s / %s bit/s' % (r.get('NewWANAccessType', '?'),
                  r.get('NewLayer1UpstreamMaxBitRate', '?'), r.get('NewLayer1DownstreamMaxBitRate', '?')))
        except Exception: pass
        def counters():
            rx = int(soap(url2, st2, 'GetTotalBytesReceived')['NewTotalBytesReceived'])
            tx = int(soap(url2, st2, 'GetTotalBytesSent')['NewTotalBytesSent'])
            return rx, tx
        def local():
            try:
                return [int(open('/sys/class/net/%s/statistics/%s' % (iface, k)).read()) for k in ('rx_bytes', 'tx_bytes')]
            except Exception: return None
        try:
            (r0, t0), l0, tm0 = counters(), local(), time.time()
            time.sleep(win)
            (r1, t1), l1, tm1 = counters(), local(), time.time()
            dt = tm1 - tm0
            delta = lambda a, b: (b - a) if b >= a else (b - a) % 2**32
            down, up = delta(r0, r1) * 8 / dt / 1e6, delta(t0, t1) * 8 / dt / 1e6
            print('    Internet traffic of the WHOLE home right now (router counters, %.0f s): down %.2f Mbit/s, up %.2f Mbit/s' % (dt, down, up))
            print('##WANDOWN=%.2f' % down); print('##WANUP=%.2f' % up)
            if l0 and l1:
                ld, lu = (l1[0] - l0[0]) * 8 / dt / 1e6, (l1[1] - l0[1]) * 8 / dt / 1e6
                print('      of which this computer: down %.2f Mbit/s, up %.2f Mbit/s -> other devices: down ~%.2f Mbit/s'
                      % (ld, lu, max(0, down - ld)))
                print('##OTHERDOWN=%.2f' % max(0, down - ld)); print('##OTHERUP=%.2f' % max(0, up - lu))
        except Exception as e:
            print('    Live WAN traffic counters: not supported by this router (%s)' % e.__class__.__name__)
    maps = []
    for idx in range(200):
        try: maps.append(soap(url, st, 'GetGenericPortMappingEntry', (('NewPortMappingIndex', idx),)))
        except Exception: break
    print('    Port forwards opened automatically through UPnP: %d' % len(maps))
    for m in maps:
        print('      %-4s external port %-6s -> %s:%-6s enabled=%s lease=%ss  "%s"' % (
            m.get('NewProtocol', ''), m.get('NewExternalPort', ''), m.get('NewInternalClient', ''),
            m.get('NewInternalPort', ''), m.get('NewEnabled', ''), m.get('NewLeaseDuration', ''),
            m.get('NewPortMappingDescription', '')))
    print('##MAPS=%d' % len(maps))
PY
    grep -v '^##' "$UPNPOUT"
    [ -s "$UPNPDEV" ] || echo "    (If nothing answered, UPnP may be off - or the local firewall blocked the replies.)"
    WANCLASS=$(val WANCLASS "$UPNPOUT"); WANIP=$(val WANIP "$UPNPOUT"); IGD=$(val IGD "$UPNPOUT"); MAPS=$(val MAPS "$UPNPOUT")
    OTHERDOWN=$(val OTHERDOWN "$UPNPOUT"); WANDOWN=$(val WANDOWN "$UPNPOUT"); WANUPTIME=$(val WANUPTIME "$UPNPOUT")
    [ "$IGD" = "1" ] && finding 3 POSSIBLE SECURITY "UPnP is enabled on the router. It helps games and video calls, but any device (including malware) can open ports to the internet. Keep it only if needed and review the port forwards listed in section 5."
    isnum "${MAPS:-}" && [ "$MAPS" -gt 0 ] && finding 3 POSSIBLE SECURITY "$MAPS port forward(s) were opened through UPnP (listed in section 5). Check that every internal IP belongs to a device you recognise."
    [ "$WANCLASS" = "private" ] && finding 2 CONFIRMED PERF "Double NAT: your router's WAN address is private, so it sits behind another router/modem. This adds a hop, breaks UPnP/port forwarding and can add latency. Put the ISP modem in bridge mode, or use only one router."
    [ "$WANCLASS" = "cgnat" ] && finding 3 CONFIRMED PERF "Your ISP uses Carrier-Grade NAT (shared public IP). Speed is not reduced directly, but port forwarding, some games and P2P will not work well. Ask your ISP for a public IP if needed."
    grep -q '^##OLDLIBUPNP=' "$UPNPOUT" && finding 2 CONFIRMED SECURITY "A device on your network uses an old UPnP library with known remote-execution flaws ($(val OLDLIBUPNP "$UPNPOUT")). Update its firmware."
    grep -q '^##OLDKERNEL=' "$UPNPOUT" && finding 3 POSSIBLE SECURITY "A device ($(val OLDKERNEL "$UPNPOUT")) reports a Linux 2.x kernel. That suggests very old firmware. Check for a firmware update."
    if isnum "${WANUPTIME:-}" && [ "$WANUPTIME" -lt 86400 ]; then
      finding 3 POSSIBLE STABILITY "The router's internet connection has only been up for $((WANUPTIME / 3600)) h $(((WANUPTIME % 3600) / 60)) min. If nobody restarted it, the line may be dropping."
    fi
  fi
else
  echo "No gateway - skipped."
fi

# ==================================================================== 6 ===
section "6. DEVICES ON YOUR NETWORK"
DEVCOUNT=0; UNKNOWN=()
if [ -n "$MYIP" ] && [ -n "$IF" ] && have ping; then
  BASE=${MYIP%.*}
  [ "$PREFIX" -lt 24 ] && echo "NOTE: your subnet is /$PREFIX (bigger than /24); only $BASE.0/24 is scanned."
  echo "Discovering devices: one ping per address. Devices that ignore ping are still found through ARP..."
  # NOTE: always wait for explicit PIDs. A bare 'wait' would also wait for the
  # report's 'tee' process substitution (bash >= 5.1) and hang forever.
  pids=()
  for i in $(seq 1 254); do
    ping -n -c1 -W1 "$BASE.$i" >/dev/null 2>&1 & pids+=($!)
    if [ ${#pids[@]} -ge 50 ]; then wait "${pids[@]}"; pids=(); fi
  done
  [ ${#pids[@]} -gt 0 ] && wait "${pids[@]}"
  sleep 1
  ip -4 neigh show dev "$IF" 2>/dev/null | awk -v b="$BASE." '$2=="lladdr" && index($1,b)==1 {print $1, $3, $NF}' | sort -t. -k4,4n -u > "$TMP/neigh"
  pids=()
  while read -r ip _ _; do
    ( n=$(timeout 2 getent hosts "$ip" 2>/dev/null | awk '{print $2; exit}')
      [ -z "$n" ] && have avahi-resolve && n=$(timeout 2 avahi-resolve -a "$ip" 2>/dev/null | awk '{print $2; exit}')
      echo "$n" > "$TMP/name_$ip" ) & pids+=($!)
  done < "$TMP/neigh"
  [ ${#pids[@]} -gt 0 ] && wait "${pids[@]}"
  printf '    %-15s %-17s %-31s %-28s %s\n' "IP" "MAC" "Vendor (from MAC)" "Name (DNS/mDNS)" "UPnP description"
  printf '    %-15s %-17s %-31s %-28s %s\n' "$MYIP" "${MYMAC:-?}" "$(oui "${MYMAC:-00}")" "$(uname -n)" "<- THIS COMPUTER"
  DEVCOUNT=1
  while read -r ip mac st; do
    DEVCOUNT=$((DEVCOUNT + 1))
    vendor=$(oui "$mac"); rnd=0
    if is_random_mac "$mac"; then vendor="(private/random MAC)"; rnd=1; fi
    name=$(cat "$TMP/name_$ip" 2>/dev/null)
    up=$(awk -F'|' -v i="$ip" '$1==i{print $2" "$3; exit}' "$UPNPDEV")
    note=""; [ "$ip" = "$GW" ] && note="<- ROUTER "
    printf '    %-15s %-17s %-31s %-28s %s\n' "$ip" "$mac" "${vendor:-unknown}" "${name:--}" "$note${up}"
    if [ -z "$vendor" ] && [ -z "$name" ] && [ -z "$up" ] && [ "$ip" != "$GW" ]; then UNKNOWN+=("$ip ($mac)"); fi
  done < "$TMP/neigh"
  echo
  echo "Devices found right now: $DEVCOUNT (sleeping phones/IoT devices may be missing - the router's client list is complete)."
  echo "'private/random MAC' = phones/laptops using MAC privacy (normal for iPhone/Android/Windows)."
  if [ ${#UNKNOWN[@]} -gt 0 ]; then
    echo "Could not identify: ${UNKNOWN[*]}"
    finding 3 POSSIBLE SECURITY "${#UNKNOWN[@]} device(s) could not be identified: ${UNKNOWN[*]}. Compare them with the router's client list. Unknown devices may be IoT gadgets - or intruders."
  fi
  NV6=$(ip -6 neigh show dev "$IF" 2>/dev/null | grep -c lladdr)
  echo "IPv6 neighbours seen: ${NV6:-0}"
else
  echo "Skipped (no IP address/interface, or ping missing)."
fi

# ==================================================================== 7 ===
section "7. INTERNET & LATENCY TESTS"
ping_run() { ping -n -c "$2" -i 0.2 -W 2 "$1" > "$TMP/ping_$3" 2>&1; }
ping_sum() { # tag -> "loss avg p95 max mdev spikes"
  local f="$TMP/ping_$1" r p95 spikes
  # Uses ping's summary lines; if ping was stopped without a summary, computes them from the replies.
  r=$(awk '/packet loss/{for(i=1;i<=NF;i++) if($i~/%$/){l=$i; sub("%","",l)}}
           /^(rtt|round-trip)/{split($4,a,"/"); av=a[2]; mx=a[3]; md=a[4]}
           /time=/{ if(match($0,/time=[0-9.]+/)){t=substr($0,RSTART+5,RLENGTH-5)+0; n++; s+=t; q+=t*t; if(t>m)m=t}
                    if(match($0,/icmp_seq=[0-9]+/)){k=substr($0,RSTART+9,RLENGTH-9)+0; if(k>ms)ms=k} }
           END{ if(av=="" && n){av=s/n; mx=m; md=sqrt(q/n-av*av)}
                if(l=="" && ms){l=(ms-n)*100/ms; if(l<0)l=0; l=sprintf("%.0f",l)}
                print (l==""?100:l), (av==""?"-":sprintf("%.1f",av)), (mx==""?"-":sprintf("%.1f",mx)), (md==""?"-":sprintf("%.1f",md))}' "$f" 2>/dev/null)
  p95=$(grep -o 'time=[0-9.]*' "$f" 2>/dev/null | cut -d= -f2 | sort -n | awk '{a[NR]=$1} END{if(NR){i=int(NR*0.95); if(i<1)i=1; print a[i]} else print "-"}')
  spikes=$(grep -o 'time=[0-9.]*' "$f" 2>/dev/null | cut -d= -f2 | awk '$1>100{c++} END{print c+0}')
  set -- $r; echo "${1:-100} ${2:--} ${p95:--} ${3:--} ${4:--} ${spikes:-0}"
}
if have ping; then
  sub "Latency & packet loss ($NPING pings each, in parallel)"
  pids=()
  if [ -n "$GW" ]; then ping_run "$GW" "$NPING" gw & pids+=($!); fi
  ping_run 1.1.1.1 "$NPING" cf & pids+=($!)
  ping_run 8.8.8.8 "$NPING" gg & pids+=($!)
  wait "${pids[@]}"
  printf '    %-22s %6s %8s %8s %8s %8s %8s\n' "Target" "Loss%" "Avg ms" "p95 ms" "Max ms" "Jitter" "Spikes"
  for t in gw cf gg; do
    [ -f "$TMP/ping_$t" ] || continue
    read -r L A P M J K < <(ping_sum $t)
    case $t in gw) lbl="Router $GW"; GW_L=$L; GW_A=$A; GW_P=$P; GW_J=$J; GW_K=$K ;;
               cf) lbl="Cloudflare 1.1.1.1"; CF_L=$L; CF_A=$A; CF_P=$P ;;
               gg) lbl="Google 8.8.8.8"; GG_L=$L; GG_A=$A ;; esac
    printf '    %-22s %6s %8s %8s %8s %8s %8s\n' "$lbl" "$L" "$A" "$P" "$M" "$J" "$K"
  done
  echo "    (Jitter = mdev; Spikes = replies slower than 100 ms. Healthy Wi-Fi to the router: avg < 5 ms, p95 < 20 ms, 0% loss)"

  if [ "${GW_L:-}" = "100" ] && lt "${CF_L:-100}" 100; then
    echo "    NOTE: the router does not answer ping (blocked) - router latency could not be measured."
  elif [ -n "${GW_L:-}" ]; then
    if gt "$GW_L" 2; then finding 1 CONFIRMED STABILITY "${GW_L}% packet loss between this computer and the router. The problem is the Wi-Fi link itself."
    elif gt "$GW_L" 0; then finding 2 CONFIRMED STABILITY "${GW_L}% packet loss to the router (should be 0% on Wi-Fi)."; fi
    if gt "$GW_A" 20 || gt "$GW_P" 60; then
      finding 1 CONFIRMED PERF "High and unstable latency to the router (avg ${GW_A} ms, p95 ${GW_P} ms, ${GW_K} spikes >100 ms). The local Wi-Fi is congested or interfered with."
    elif gt "$GW_A" 8 || gt "$GW_P" 25; then
      finding 2 CONFIRMED PERF "Elevated latency/jitter to the router (avg ${GW_A} ms, p95 ${GW_P} ms). Good Wi-Fi is < 5 ms average."
    fi
    if [ "${PS:-}" = "on" ] && { gt "$GW_P" 20 || gt "$GW_J" 5; }; then
      finding 2 POSSIBLE PERF "Wi-Fi power saving is ON on this computer while router latency is jittery. Power saving can add latency spikes (test: 'sudo iw dev $WIFI_IF set power_save off', temporary until reboot)."
    elif [ "${PS:-}" = "on" ]; then
      finding 3 POSSIBLE PERF "Wi-Fi power saving is ON on this computer. It can cause occasional latency spikes on some drivers."
    fi
  fi
  if [ -n "${CF_L:-}" ] && gt "$CF_L" 1 && ! gt "${GW_L:-0}" 1; then
    finding 1 CONFIRMED STABILITY "${CF_L}% packet loss to the internet, while the Wi-Fi link to the router is clean. The loss happens beyond your router: modem, line or ISP."
  fi
  if isnum "${CF_A:-}" && isnum "${GW_A:-}"; then
    WANLAT=$(calc "$CF_A-$GW_A"); echo "    Latency added beyond your router (ISP path to Cloudflare): ~${WANLAT} ms"
    gt "$WANLAT" 80 && finding 2 POSSIBLE PERF "High latency beyond your router (~${WANLAT} ms to Cloudflare). This is the ISP route/line, not Wi-Fi."
  fi
fi

sub "DNS speed (10 popular domains per server)"
declare -A SEEN=(); DNSLIST=""
for d in $SYSDNS; do [ -z "${SEEN[$d]:-}" ] && { SEEN[$d]=1; DNSLIST+="system=$d,"; }; done
[ -n "$GW" ] && [ -z "${SEEN[$GW]:-}" ] && { SEEN[$GW]=1; DNSLIST+="router=$GW,"; }
for p in cloudflare=1.1.1.1 google=8.8.8.8 quad9=9.9.9.9; do d=${p#*=}; [ -z "${SEEN[$d]:-}" ] && { SEEN[$d]=1; DNSLIST+="$p,"; }; done
NXCHECK="$(echo $SYSDNS | tr ' ' ','),${GW:-}"
DNSOUT="$TMP/dns"
if have python3; then
  python3 -I - "${DNSLIST%,}" "$NXCHECK" > "$DNSOUT" 2>&1 <<'PY'
import socket, struct, random, time, sys
pairs = [p.split('=', 1) for p in sys.argv[1].split(',') if '=' in p]
nx = set(sys.argv[2].split(','))
domains = ['google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'amazon.com',
           'microsoft.com', 'apple.com', 'whatsapp.com', 'netflix.com', 'tiktok.com']
def query(server, name, timeout=2.0):
    tid = random.randint(0, 65535)
    pkt = struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 0) + b''.join(
        bytes([len(p)]) + p.encode() for p in name.split('.')) + b'\x00' + struct.pack('>HH', 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(timeout)
    try:
        t0 = time.perf_counter(); s.sendto(pkt, (server, 53))
        while True:
            data, _ = s.recvfrom(4096)
            if len(data) >= 12 and struct.unpack('>H', data[:2])[0] == tid: break
        ms = (time.perf_counter() - t0) * 1000
        flags, _, an = struct.unpack('>HHH', data[2:8])
        return ms, flags & 0xF, an
    except OSError:
        return None, None, None
    finally:
        s.close()
print('    %-28s %9s %9s %9s  %s' % ('DNS server', 'median', 'max', 'timeouts', 'notes'))
for label, ip in pairs:
    times, to = [], 0
    for d in domains:
        ms, rc, an = query(ip, d)
        if ms is None:
            to += 1
            if to >= 3 and not times: break
        else:
            times.append(ms)
    hij, note = 0, ''
    if times and ip in nx:
        ms, rc, an = query(ip, 'nx%08x-check.com' % random.getrandbits(32))
        if rc == 0 and an:
            hij, note = 1, 'answers NON-EXISTENT domains (NXDOMAIN hijacking)'
    times.sort()
    med = times[len(times) // 2] if times else -1
    mx = times[-1] if times else -1
    if not times: note = 'NOT RESPONDING'
    print('    %-28s %9s %9s %9d  %s' % ('%s (%s)' % (label, ip), ('%.0f ms' % med) if times else '-',
          ('%.0f ms' % mx) if times else '-', to, note))
    print('##DNS|%s|%s|%.1f|%.1f|%d|%d|%d' % (label, ip, med, mx, to, len(times), hij))
PY
  grep -v '^##' "$DNSOUT"
  BESTPUB=$(awk -F'|' '($2=="cloudflare"||$2=="google"||$2=="quad9") && $7>0 {print $5}' "$DNSOUT" | sort -n | head -1)
  while IFS='|' read -r _ lbl ip med mx to ok hij; do
    [ "$lbl" = "system" ] || continue
    if [ "$ok" = "0" ]; then finding 1 CONFIRMED STABILITY "The DNS server this computer uses ($ip) did not answer. Websites will fail or load very slowly."
    else
      [ "$to" -gt 0 ] && finding 2 CONFIRMED STABILITY "The DNS server $ip dropped $to of 10 lookups. Pages sometimes hang for seconds before loading."
      if isnum "$BESTPUB" && gt "$med" 40 && gt "$med" "$(calc "$BESTPUB*2")"; then
        finding 2 CONFIRMED PERF "Slow DNS: your DNS server $ip takes ${med} ms (median) vs ${BESTPUB} ms for the best public resolver. Every new website waits for this."
      fi
    fi
    [ "$hij" = "1" ] && finding 3 CONFIRMED SECURITY "DNS server $ip returns addresses for non-existent domains (NXDOMAIN hijacking, usually ISP ad redirection)."
    case "$ip" in "$GW"|10.*|192.168.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|1.1.1.1|1.0.0.1|8.8.8.8|8.8.4.4|9.9.9.9|149.112.112.112|208.67.222.222|208.67.220.220|94.140.14.14|94.140.15.15) ;;
      *) finding 3 POSSIBLE SECURITY "This computer uses DNS server $ip. It is neither your router nor a well-known public resolver. Check that it belongs to your ISP (malware sometimes changes router DNS)." ;;
    esac
  done < <(grep '^##DNS|' "$DNSOUT")
fi

sub "Public IP / NAT check"
CFT=$(curl -4 -s -m 8 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null)
CFIP=$(sed -n 's/^ip=//p' <<<"$CFT"); COLO=$(sed -n 's/^colo=//p' <<<"$CFT"); CLOC=$(sed -n 's/^loc=//p' <<<"$CFT")
echo "    Public IPv4 (masked): $(mask_ip "$CFIP")   Cloudflare edge: ${COLO:-?}   Country: ${CLOC:-?}"
if [ -n "${WANIP:-}" ] && [ -n "$CFIP" ]; then
  if [ "$WANIP" = "$CFIP" ]; then echo "    Router WAN IP = public IP -> no CGNAT, no double NAT."
  else echo "    Router WAN IP differs from the public IP -> NAT in front of the router (or a VPN on this computer)."; fi
fi

sub "Route to the internet"
TRACE="$TMP/trace"; : > "$TRACE"
if have mtr; then
  mtr -n -r -w -c "$MTRC" -m 15 1.1.1.1 > "$TRACE" 2>&1; sed 's/^/    /' "$TRACE"
  HOPS=$(awk '$1 ~ /^[0-9]+\.\|--$/ {h=$1; sub(/\.\|--/,"",h); print h, $2}' "$TRACE")
elif have tracepath; then
  tracepath -n -m 15 1.1.1.1 > "$TRACE" 2>&1; sed 's/^/    /' "$TRACE"
  HOPS=$(awk '$1 ~ /^[0-9]+:$/ && $2 ~ /^[0-9.]+$/ {h=$1; sub(":","",h); if(!(h in s)){s[h]=1; print h, $2}}' "$TRACE")
else
  HOPS=""; echo "    (tracepath/mtr not installed)"
fi
H2=$(awk '$1==2{print $2}' <<<"$HOPS")
if [ -z "${WANCLASS:-}" ] && is_private_ip "$H2"; then
  finding 3 POSSIBLE PERF "The 2nd hop ($H2) is a private address. This may be double NAT (two routers in a row), or simply your ISP's internal network. Check whether the ISP modem is also routing."
fi
for ip in $(awk '$1<=4{print $2}' <<<"$HOPS"); do
  if is_cgnat_ip "$ip" && [ -z "${WANCLASS:-}" ]; then
    finding 3 POSSIBLE PERF "A hop in 100.64.0.0/10 ($ip) suggests Carrier-Grade NAT by your ISP."; break
  fi
done

sub "MTU (largest packet size without fragmentation)"
if have ping && ping -n -c 3 -i 0.3 -W 4 1.1.1.1 >/dev/null 2>&1; then
  # A size counts as OK if ANY of 3 probes gets a reply within 4 s: on a slow,
  # congested line a single late reply must not be mistaken for "too big".
  mtu_ok() { ping -n -c 3 -i 0.3 -W 4 -M do -s "$1" 1.1.1.1 2>&1 | tee "$TMP/mtu_last" | grep -q ' bytes from '; }
  if mtu_ok 1472; then PMTU=1500
  else
    HINT=$(grep -oE 'mtu ?= ?[0-9]+' "$TMP/mtu_last" | grep -oE '[0-9]+' | head -1)
    lo=1172; hi=1472
    if isnum "${HINT:-}" && [ "$HINT" -lt 1500 ] && [ "$HINT" -ge 1200 ] && mtu_ok $((HINT - 28)); then lo=$((HINT - 28)); hi=$((HINT - 27)); fi
    while [ $((hi - lo)) -gt 1 ]; do mid=$(((lo + hi) / 2)); if mtu_ok $mid; then lo=$mid; else hi=$mid; fi; done
    if mtu_ok $lo; then PMTU=$((lo + 28)); else PMTU="?"; fi
  fi
  IFMTU=$(cat "/sys/class/net/${IF:-lo}/mtu" 2>/dev/null)
  echo "    Path MTU to the internet: $PMTU   Interface MTU: ${IFMTU:-?}   (1500 = normal Ethernet/cable, 1492 = normal for PPPoE DSL/fiber)"
  if isnum "$PMTU" && [ "$PMTU" -lt 1400 ]; then
    finding 3 POSSIBLE PERF "Low path MTU ($PMTU). Fragmentation or a tunnel may slow some connections. Check the router's WAN MTU setting."
  fi
else
  echo "    Skipped (ICMP to 1.1.1.1 not possible)."
fi

sub "IPv6"
V6=$(ip -6 addr show dev "${IF:-lo}" scope global 2>/dev/null | grep -c 'inet6')
if [ "${V6:-0}" -gt 0 ]; then
  echo "    Global IPv6 addresses on $IF: $V6 (addresses not shown for privacy)"
  if have ping && ping -6 -n -c 5 -i 0.2 -W 2 2606:4700:4700::1111 > "$TMP/ping6" 2>&1; then
    echo "    IPv6 internet: working ($(grep -o 'rtt.*' "$TMP/ping6"))"
  else
    echo "    IPv6 internet: NOT working"
    finding 2 CONFIRMED STABILITY "IPv6 addresses are configured but IPv6 internet does not work. Apps try IPv6 first, so some sites or apps start slowly. Fix IPv6 on the router or ask the ISP."
  fi
else
  echo "    No global IPv6 address (IPv4 only - this is fine)."
fi

DL=""; UL=""
if [ "$SPEEDTEST" -eq 1 ]; then
  sub "Speed test (Cloudflare) + latency under load (bufferbloat)"
  echo "    Downloading, then uploading, for at most 15 s each (4 parallel streams)."
  echo "    On slow lines other devices will be slower for those ~30 s."
  stop_ping() { # SIGINT makes ping print its summary; SIGTERM is the fallback
    kill -INT "$1" 2>/dev/null
    for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$1" 2>/dev/null || break; sleep 0.2; done
    kill "$1" 2>/dev/null; wait "$1" 2>/dev/null
  }
  run_load() { # down|up -> prints Mbit/s ; pings 1.1.1.1 in parallel into $TMP/ping_$1
    local kind=$1 pids=() t0 t1 total
    : > "$TMP/bytes_$kind"
    if have ping; then ping -n -i 0.2 -W 2 1.1.1.1 > "$TMP/ping_$kind" 2>&1 & PP=$!; else PP=""; fi
    sleep 1
    t0=$(date +%s.%N)
    for k in 1 2 3 4; do
      if [ "$kind" = down ]; then
        curl -s -m 15 -o /dev/null -w '%{size_download}\n' "https://speed.cloudflare.com/__down?bytes=25000000" >> "$TMP/bytes_$kind" &
      else
        curl -s -m 15 -o /dev/null -w '%{size_upload}\n' -H 'Content-Type: application/octet-stream' --data-binary @"$TMP/up.bin" "https://speed.cloudflare.com/__up" >> "$TMP/bytes_$kind" &
      fi
      pids+=($!)
    done
    wait "${pids[@]}"
    t1=$(date +%s.%N)
    [ -n "$PP" ] && stop_ping "$PP"
    total=$(awk '{s+=$1} END{print s+0}' "$TMP/bytes_$kind")
    awk -v b="$total" -v a="$t0" -v c="$t1" 'BEGIN{ if(b>0 && c>a) printf "%.1f", b*8/(c-a)/1e6 }'
  }
  head -c 10000000 /dev/zero > "$TMP/up.bin"
  DL=$(run_load down); UL=$(run_load up)
  read -r DLL DLA DLP _ < <(ping_sum down 2>/dev/null)
  read -r ULL ULA ULP _ < <(ping_sum up 2>/dev/null)
  echo "    Download: ${DL:-failed} Mbit/s     Upload: ${UL:-failed} Mbit/s"
  echo "    Latency idle: ${CF_A:-?} ms | while downloading: avg ${DLA:-?} / p95 ${DLP:-?} ms | while uploading: avg ${ULA:-?} / p95 ${ULP:-?} ms"
  if isnum "${CF_A:-}"; then
    for kind in down up; do
      if [ $kind = down ]; then LA=${DLA:-}; else LA=${ULA:-}; fi
      isnum "$LA" || continue
      BB=$(calc "$LA-$CF_A")
      echo "    Bufferbloat ($kind): +${BB} ms  ($(awk -v b="$BB" 'BEGIN{print (b<30)?"good":(b<100)?"moderate":"BAD"}'))"
      if gt "$BB" 100; then finding 1 CONFIRMED PERF "Severe bufferbloat: latency jumps by +${BB} ms while ${kind}loading. Calls, games and browsing lag whenever anyone downloads/uploads. Enable SQM / Smart Queue / 'QoS with bandwidth limits' on the router."
      elif gt "$BB" 30; then finding 2 CONFIRMED PERF "Moderate bufferbloat: +${BB} ms latency while ${kind}loading. SQM/Smart QoS on the router would help."; fi
    done
  fi
  if isnum "$DL"; then
    if [ -n "$PLAN" ]; then
      PCT=$(calc "$DL*100/$PLAN"); echo "    You get ${PCT}% of your ${PLAN} Mbit/s plan over this connection."
      if lt "$PCT" 60; then
        if isnum "$RXRATE" && gt "$DL" "$(calc "$RXRATE*0.45")"; then
          finding 1 CONFIRMED PERF "Only ${PCT}% of your plan (${DL}/${PLAN} Mbit/s), and the Wi-Fi link rate (${RXRATE} Mbit/s) is the limit. Improve the Wi-Fi link: 5 GHz, wider channel, better signal."
        else
          finding 1 CONFIRMED PERF "Only ${PCT}% of your plan (${DL}/${PLAN} Mbit/s), although the Wi-Fi link rate (${RXRATE:-?} Mbit/s) allows more. The limit is beyond Wi-Fi: other devices' traffic, router, modem or ISP. Confirm with a wired (Ethernet) test."
        fi
      fi
    elif isnum "$RXRATE" && gt "$DL" "$(calc "$RXRATE*0.45")"; then
      finding 2 POSSIBLE PERF "Measured ${DL} Mbit/s is close to what this Wi-Fi link (${RXRATE} Mbit/s PHY) can carry. Wi-Fi is probably your speed limit, not the internet plan."
    fi
  fi
fi
if isnum "${OTHERDOWN:-}" && gt "$OTHERDOWN" 5; then
  finding 2 CONFIRMED PERF "Other devices were using ~${OTHERDOWN} Mbit/s of internet download during the test (router counters). Find which one in the router's traffic statistics."
fi

# ==================================================================== 8 ===
section "8. THIS COMPUTER: BACKGROUND TRAFFIC & INTERFACE ERRORS"
if [ -n "$IF" ] && [ -r "/sys/class/net/$IF/statistics/rx_bytes" ]; then
  R0=$(cat "/sys/class/net/$IF/statistics/rx_bytes"); T0=$(cat "/sys/class/net/$IF/statistics/tx_bytes")
  sleep "$WIN"
  R1=$(cat "/sys/class/net/$IF/statistics/rx_bytes"); T1=$(cat "/sys/class/net/$IF/statistics/tx_bytes")
  LDOWN=$(calc "($R1-$R0)*8/$WIN/1000000"); LUP=$(calc "($T1-$T0)*8/$WIN/1000000")
  echo "Traffic on $IF over ${WIN}s while idle: down $LDOWN Mbit/s, up $LUP Mbit/s"
  gt "$LDOWN" 2 && finding 2 CONFIRMED PERF "This computer itself is downloading in the background (~$LDOWN Mbit/s while idle). See the process list in section 8."
  gt "$LUP" 2 && finding 2 CONFIRMED PERF "This computer itself is uploading in the background (~$LUP Mbit/s while idle). Cloud sync or backup? See section 8."
fi
sub "Programs with the most open internet connections (this user's programs)"
ss -tunpH state established 2>/dev/null | grep -o 'users:(("[^"]*"' | cut -d'"' -f2 | sort | uniq -c | sort -rn | head -10 | sed 's/^/    /'
sub "Download / sync / update programs running now"
RUNNING=$(ps -eo pid=,comm= 2>/dev/null | awk '$2 ~ /^(dnf|dnf5|packagekitd|gnome-software|flatpak|rpm-ostree|steam|transmission|qbittorrent|deluged|deluge|ktorrent|fragments|dropbox|onedrive|insync|syncthing|nextcloud|megasync|rclone|aria2c|yt-dlp|wget|apt|apt-get|unattended-upgr)/ {print "    " $1 " " $2}')
echo "${RUNNING:-    none detected}"
sub "Interface error counters"
ip -s link show dev "${IF:-lo}" 2>/dev/null | sed 's/^/    /'

# ==================================================================== 9 ===
section "9. RECENT WI-FI DISCONNECTIONS (logs, last 24 h)"
if have journalctl; then
  J=$(journalctl --no-pager -q -o short-iso --since "-24h" -u NetworkManager -u wpa_supplicant -u iwd 2>/dev/null \
      | grep -iE 'CTRL-EVENT-DISCONNECTED|deauthenticat|disassociat|beacon loss|state change: activated -> (deactivating|failed|disconnected)')
  K=$(journalctl --no-pager -q -k -o short-iso --since "-24h" 2>/dev/null \
      | grep -iE 'deauthenticat|disassociat|beacon loss|connection loss|firmware crash|Microcode SW error|hardware restart|fw crash' )
  if [ -z "$J$K" ]; then
    if [ -z "$(journalctl -q -n1 -u NetworkManager 2>/dev/null)" ]; then
      echo "Cannot read system logs as this user. Optional: run 'sudo journalctl -u NetworkManager --since -24h' yourself."
    else
      echo "No Wi-Fi disconnections logged in the last 24 h."
    fi
  else
    echo "$J" | tail -20 | sed 's/^/    /'; echo "$K" | tail -15 | sed 's/^/    /'
    # Count drops NOT initiated by this computer (suspend/user actions are locally generated)
    NDROP=$(grep 'CTRL-EVENT-DISCONNECTED' <<<"$J" | grep -vc 'locally_generated=1')
    [ "${NDROP:-0}" -eq 0 ] && NDROP=$(grep -ciE 'deauthenticated|disassociated from|beacon loss|connection loss' <<<"$K")
    echo "Disconnections not caused by this computer: ${NDROP:-0}"
    [ "${NDROP:-0}" -ge 3 ] && finding 1 CONFIRMED STABILITY "Wi-Fi dropped ${NDROP} times in the last 24 h, not caused by this computer (router deauth, signal loss or interference). See the reason codes in section 9."
    grep -qiE 'firmware crash|Microcode SW error|hardware restart|fw crash' <<<"$K" && finding 1 CONFIRMED STABILITY "The Wi-Fi driver/firmware on this computer crashed recently. Update the system (sudo dnf upgrade --refresh) and the linux-firmware package."
  fi
else
  echo "journalctl not available."
fi

# =================================================================== 10 ===
section "10. FINDINGS - sorted by impact (HIGH first)"
if [ ${#FINDINGS[@]} -eq 0 ]; then
  echo "No problems detected by the automatic checks."
else
  printf '%s\n' "${FINDINGS[@]}" | sort -s -t'|' -k1,1n -k2,2n -k3,3n | awk -F'|' '{
    sev=($1==1?"HIGH":($1==2?"MEDIUM":"LOW")); printf "%2d. [%-6s] [%-9s] [%-9s] %s\n", NR, sev, $4, $5, $6 }'
fi
echo
echo "CONFIRMED = measured directly in this test.  POSSIBLE = strong indication, but needs checking on the router."

# =================================================================== 11 ===
section "11. NOT VISIBLE FROM A COMPUTER - check in the router admin page"
cat <<'EOF'
  * Per-device internet usage (Traffic statistics / Bandwidth control / QoS page)
  * Firmware version and whether an update is available (System / Firmware upgrade)
  * QoS / SQM / Smart Queue settings, DHCP range and lease time, DNS servers handed out
  * Wireless settings: channel & width for each band, band steering, WMM, airtime fairness, WPS
  * Full client list (including sleeping devices), remote management (WAN access), admin password
  Screenshots of these pages (hide any passwords) complete the analysis.
EOF
echo
echo "Finished in $(( $(date +%s) - START_TS )) s. Report saved to: $(pwd)/$REPORT"
