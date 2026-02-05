#!/bin/bash
if [ -t 1 ]; then clear; fi # Clear screen if we have a console
#---------------------------------------------------------------------------
# Sonar - Version 1.0 Initial version
#---------------------------------------------------------------------------
#
# Script to monitor for ICMP ping agains the machin this script runs on.
# It is intended to run on kali linux with xfce4 graphical environment.
# when Pinged a popup will appear asking the user what action to take:
#
# 1. Go Offline
# 2. Change IP of this host
# 3. Block the client pinging
# 4. Allow all trafic from the client pinging to this host
#
# (C)opyleft 2025 - Keld Norman
#---------------------------------------------------------------------------
# Essential variable
#---------------------------------------------------------------------------
PROGNAME="${0##*/}" ; PROGNAME="${PROGNAME%%.*}" # /x/y/z.sh -> z
TEMP_DIR="/tmp/${PROGNAME}"                 # Temp directory
#---------------------------------------------------------------------------
# Variables
#---------------------------------------------------------------------------
DEBUG=0                                     # Set to one to enable debugging
CLEANED_UP=0                                #
MENU_WIDTH=520                              # Width of dialog popup
ULOGD_GROUP=42                              #
MAIN_PID=${BASHPID}                         #
ISOLATE_TIME_SEC=300                        # Seconds to isolate attacker
TITLE="Sonar Ping Detected"                 #
INCLUDE_LOCAL="${INCLUDE_LOCAL:-0}"         #
ULOGD_CONF="${TEMP_DIR}/ulogd.conf"         #
LOCKFILE="${TEMP_DIR}/${PROGNAME}.lock"     #
SCRIPT_PATH="${REAL_HOME}/bin/${PROGNAME}.sh" # Where this script is located
IGNORE_IP_LIST="${TEMP_DIR}/ignore.list"    #
ISOLATE_MARKER_DIR="${TEMP_DIR}/isolating"  #
#---------------------------------------------------------------------------
# Debugging and log files
#---------------------------------------------------------------------------
LOG_FILE="/var/log/${PROGNAME}.log"         # Normal logfile
DEBUG_LOG="/var/log/${PROGNAME}.debug.log"  # Debug logfile
#---------------------------------------------------------------------------
# IPTables Chain names
#---------------------------------------------------------------------------
ALLOW_CHAIN="ICMP_WATCHER_ALLOW"            #
BLOCK_CHAIN="ICMP_WATCHER_BLOCK"            #
ISO_CHAIN_IN="ICMP_WATCHER_ISO_IN"          #
ISO_CHAIN_OUT="ICMP_WATCHER_ISO_OUT"        #
#---------------------------------------------------------------------------
# Systemd service file name
#---------------------------------------------------------------------------
SERVICE_FILE="/etc/systemd/system/${PROGNAME}.service"
#---------------------------------------------------------------------------
# USER / DISPLAY CONTEXT
#---------------------------------------------------------------------------
DISPLAY_VAL="${DISPLAY:-:0.0}"
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(getent passwd "$REAL_USER" | awk -F: '{print $6}')"
XAUTH_FILE="${XAUTHORITY:-${REAL_HOME}/.Xauthority}"
#---------------------------------------------------------------------------
# SAVE IP, IP FORWARD AND ICMP IGNORE SETTINGS
#---------------------------------------------------------------------------
ORIG_IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)
ORIG_ICMP_IGNORE=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_all 2>/dev/null || echo 0)
LOCAL_IPS="$(ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1 | grep -v '^127\.0\.0\.1$' | tr '\n' ' ' | sed 's/ *$//')"
#---------------------------------------------------------------------------
# Setup BASE DIR and UMASK
#---------------------------------------------------------------------------
umask 077 # Set strict umask: only the owner can read/write/execute new files/dirs
mkdir -p -m 700 "${TEMP_DIR}" 2>/dev/null # Ensure the base directory is private
#---------------------------------------------------------------------------
# DEBUG
#---------------------------------------------------------------------------
if [ "${DEBUG:-0}" -eq 1 ]; then
 sudo -n rm -f "${DEBUG_LOG}" 2>/dev/null # Clean up legacy log if it exists
 sudo -n touch "${DEBUG_LOG}" 2>/dev/null
 sudo -n chmod 0640 "${DEBUG_LOG}" 2>/dev/null
 echo "--- Script started at $(date) ---" | sudo -n tee "${DEBUG_LOG}" >/dev/null
 # Note: exec redirection to root-owned file will still fail if script is not run as root.
 # But we assume it runs as root via service or with sudo.
 exec > >(sudo -n tee -a "${DEBUG_LOG}") 2>&1
 set -x
else
 set +x
fi
#---------------------------------------------------------------------------
# LOGGING
#---------------------------------------------------------------------------
log_msg(){
 local prefix="$1"
 local msg="$2"
 printf "\r[%s] %s %s\n" "${prefix}" "$(date '+%Y-%m-%d %H:%M:%S')" "${msg}"
}
#---------------------------------------------------------------------------
# DEPENDENCY CHECK
#---------------------------------------------------------------------------
check_sudo(){
 if ! sudo -n true 2>/dev/null; then
  log_msg "!" "ERROR: Passwordless sudo is required for user '${REAL_USER}'."
  printf "\nPlease add the following line to a file in /etc/sudoers.d/ (e.g., /etc/sudoers.d/sonar):\n"
  printf "${REAL_USER} ALL=(ALL) NOPASSWD: /usr/sbin/iptables, /usr/sbin/ip6tables, /usr/sbin/ulogd, /usr/bin/nmcli, /usr/bin/macchanger, /usr/bin/pkill, /usr/bin/tee, /usr/bin/chmod, /usr/bin/chown, /usr/bin/rm, /usr/bin/touch\n\n"
  exit 1
 fi
}
ensure_pkg(){
 local cmd="$1"
 local pkg="$2"
 if ! command -v "$cmd" >/dev/null 2>&1; then
  sudo -n apt-get update -qq && sudo -n apt-get install -y "$pkg" || exit 1
  if [ "$pkg" = "ulogd2" ]; then
   sudo -n systemctl disable ulogd2 >/dev/null 2>&1 || true
  fi
 fi
}
#---------------------------------------------------------------------------
# GTK THEME PICKER (SCRIPT-LOCAL)
#---------------------------------------------------------------------------
pick_gtk_theme(){
 local wanted="Kali-Slate-Dark"
 if [ -d "/usr/share/themes/${wanted}" ] || [ -d "${REAL_HOME}/.themes/${wanted}" ]; then
  export GTK_THEME="${wanted}"
 else
  unset GTK_THEME
fi
}
#---------------------------------------------------------------------------
# HELPERS
#---------------------------------------------------------------------------
get_gateway(){
 ip route show default dev "${NETCARD}" 2>/dev/null | awk '/default/ {print $3}' | head -n1
}
ip_is_local(){
 echo " ${LOCAL_IPS} " | grep -q " $1 "
}
should_ignore_ip(){
 [ -s "${IGNORE_IP_LIST}" ] || return 1
 grep -q -F "$1" "${IGNORE_IP_LIST}"
}
validate_netcard(){
 NETCARDS="$(nmcli -f DEVICE,TYPE device | egrep -v '^lo |^p2p|^DEVICE')"
 if echo "${NETCARDS}" | awk '$2=="ethernet"{print $1}' | grep -qw "${NETCARD}"; then
  NETCARD_TYPE="ethernet"
 elif echo "${NETCARDS}" | awk '$2=="wifi"{print $1}' | grep -qw "${NETCARD}"; then
  NETCARD_TYPE="wifi"
 else
  NETCARD_TYPE="unknown"
 fi
}
same_subnet_on_iface(){
 local dst="$1"
 local route
 route="$(ip route get "$dst" 2>/dev/null | head -n1)"
 echo "$route" | grep -q " dev ${NETCARD} " || return 1
 echo "$route" | grep -q " via " && return 1
 return 0
}
#---------------------------------------------------------------------------
# LOCK (PID-BASED, STALE-SAFE)
#---------------------------------------------------------------------------
lock_acquire(){
 local lockfile="$1"
 if [ -f "${lockfile}" ]; then
  oldpid="$(cat "${lockfile}" 2>/dev/null)"
  if [ -n "${oldpid}" ] && kill -0 "${oldpid}" 2>/dev/null; then
   return 1
  fi
 rm -f "${lockfile}" 2>/dev/null
 fi
 echo $$ > "${lockfile}" || return 1
 return 0
}
lock_release(){
 local lockfile="$1"
 rm -f "${lockfile}" 2>/dev/null
}
#---------------------------------------------------------------------------
# IPTABLES ISOLATION CHAIN
#---------------------------------------------------------------------------
remove_firewall(){
 for cmd in iptables ip6tables; do
  for hook in INPUT FORWARD; do     # Detach main hooks
   sudo -n $cmd -D $hook -j "${ISO_CHAIN_IN}" 2>/dev/null
  done
  sudo -n $cmd -t raw -D PREROUTING -j "${ISO_CHAIN_IN}" 2>/dev/null
  sudo -n $cmd -D OUTPUT -j "${ISO_CHAIN_OUT}" 2>/dev/null
  sudo -n $cmd -D INPUT -j "${ALLOW_CHAIN}" 2>/dev/null
  sudo -n $cmd -D INPUT -j "${BLOCK_CHAIN}" 2>/dev/null
  # Delete the chains
  for chain in "${ISO_CHAIN_IN}" "${ISO_CHAIN_OUT}" "${ALLOW_CHAIN}" "${BLOCK_CHAIN}"; do
   sudo -n $cmd -F "${chain}" 2>/dev/null
   sudo -n $cmd -X "${chain}" 2>/dev/null
   sudo -n $cmd -t raw -F "${chain}" 2>/dev/null
   sudo -n $cmd -t raw -X "${chain}" 2>/dev/null
  done
 done
}
init_firewall(){
 remove_firewall
 cleanup_detection
 rm -rf "${TEMP_DIR}"
 mkdir -p -m 700 "${ISOLATE_MARKER_DIR}"
 for cmd in iptables ip6tables; do # Create chains
  sudo -n $cmd -N "${ALLOW_CHAIN}"
  sudo -n $cmd -N "${BLOCK_CHAIN}"
  sudo -n $cmd -N "${ISO_CHAIN_IN}"
  sudo -n $cmd -N "${ISO_CHAIN_OUT}"
  sudo -n $cmd -t raw -N "${ISO_CHAIN_IN}" 2>/dev/null
  #
  # Insert rules into INPUT in REVERSE priority order to avoid index issues
  # Desired order: 1:ALLOW, 2:BLOCK, 3:NFLOG, 4:DROP, 5:ISO
  #
  # 5. Isolation (Lowest priority among our rules)
  sudo -n $cmd -I INPUT -j "${ISO_CHAIN_IN}"
  # 4. Stealth (DROP)
  if [ "$cmd" = "iptables" ]; then
   sudo -n $cmd -I INPUT -p icmp --icmp-type echo-request -j DROP
  else
   sudo -n $cmd -I INPUT -p icmpv6 --icmpv6-type echo-request -j DROP 2>/dev/null
  fi
  # 3. Detection (NFLOG)
  if [ "$cmd" = "iptables" ]; then
   sudo -n $cmd -I INPUT -p icmp --icmp-type echo-request -j NFLOG --nflog-group 42
  else
   sudo -n $cmd -I INPUT -p icmpv6 --icmpv6-type echo-request -j NFLOG --nflog-group 42 2>/dev/null
  fi
  # 2. Block
  sudo -n $cmd -I INPUT -j "${BLOCK_CHAIN}"
  # 1. Allow (Highest priority)
  sudo -n $cmd -I INPUT -j "${ALLOW_CHAIN}"
  # Other hooks (Order doesn't matter much as these are usually empty or handled specifically)
  sudo -n $cmd -I FORWARD 1 -j "${ISO_CHAIN_IN}"
  sudo -n $cmd -t raw -I PREROUTING 1 -j "${ISO_CHAIN_IN}" 2>/dev/null
  sudo -n $cmd -I OUTPUT 1 -j "${ISO_CHAIN_OUT}"
 done
}
#---------------------------------------------------------------------------
#
#---------------------------------------------------------------------------
ensure_pkg sed sed
ensure_pkg awk gawk
ensure_pkg grep grep
ensure_pkg ip iproute2
ensure_pkg tr coreutils
ensure_pkg ulogd ulogd2
ensure_pkg cut coreutils
ensure_pkg zenity zenity
ensure_pkg iptables iptables
ensure_pkg timeout coreutils
ensure_pkg macchanger macchanger
ensure_pkg nmcli network-manager
ensure_pkg ettercap ettercap-text-only
ensure_pkg etterfilter ettercap-text-only
#---------------------------------------------------------------------------
# AWK parser - indestructible packet boundary detection
#---------------------------------------------------------------------------
ULOGD_AWK_SCRIPT='
function process() {
  if (type == "8" && src != "" && dst != "") {
    gsub(/[ \t]+/, "", iface); gsub(/[ \t]+/, "", src); gsub(/[ \t]+/, "", dst)
    print iface, src, dst
    fflush()
  }
  iface=src=dst=type=""
}
/^===>PACKET BOUNDARY/ { process(); next }
/^oob.in=/       { iface=$0; sub(/^oob.in=[ \t]*/, "", iface) }
/^ip.saddr.str=/ { src=$0;   sub(/^ip.saddr.str=[ \t]*/, "", src) }
/^ip.daddr.str=/ { dst=$0;   sub(/^ip.daddr.str=[ \t]*/, "", dst) }
/^icmp.type=/    { type=$0;  sub(/^icmp.type=[ \t]*/, "", type) }
END { process() }'

init_detection(){
 # Prepare ulogd config
 cat <<EOF > "${ULOGD_CONF}"
[global]
logfile="/dev/null"
stack=log1:NFLOG,base1:BASE,ifi1:IFINDEX,ip2str1:IP2STR,op1:OPRINT

[log1]
group=42

[op1]
file="/dev/stdout"
sync=1
EOF
 chmod 600 "${ULOGD_CONF}"
}
cleanup_detection(){
 sudo -n iptables -D INPUT -p icmp --icmp-type echo-request -j NFLOG --nflog-group 42 2>/dev/null
 sudo -n iptables -D INPUT -p icmp --icmp-type echo-request -j DROP 2>/dev/null
 sudo -n ip6tables -D INPUT -p icmpv6 --icmpv6-type echo-request -j NFLOG --nflog-group 42 2>/dev/null
 sudo -n ip6tables -D INPUT -p icmpv6 --icmpv6-type echo-request -j DROP 2>/dev/null
}
cleanup(){
 # Only the main process should perform the global cleanup and print the message
 [ -n "${MAIN_PID}" ] && [ "${BASHPID}" -ne "${MAIN_PID}" ] && return
 [ "${CLEANED_UP}" -eq 1 ] && return
 CLEANED_UP=1
 trap - EXIT INT TERM # Silence traps to prevent recursion
 log_msg "+" "ICMP Watcher stopping..."
 ( sudo -n pkill -KILL -f "[t]imeout.*ettercap" 2>/dev/null ) 2>/dev/null
 ( sudo -n pkill -INT -f "[e]ttercap.*-M arp" 2>/dev/null ) 2>/dev/null
 ( sudo -n pkill -TERM -f "[u]logd -c ${ULOGD_CONF}" 2>/dev/null ) 2>/dev/null
 remove_firewall
 cleanup_detection
 rm -rf "${TEMP_DIR}" 2>/dev/null
 [ -n "${ORIG_IP_FORWARD}" ] && echo "${ORIG_IP_FORWARD}" | sudo -n tee /proc/sys/net/ipv4/ip_forward >/dev/null 2>&1
 [ -n "${ORIG_ICMP_IGNORE}" ] && echo "${ORIG_ICMP_IGNORE}" | sudo -n tee /proc/sys/net/ipv4/icmp_echo_ignore_all >/dev/null 2>&1
 exit 0
}
#---------------------------------------------------------------------------
# ZENITY WRAPPER (RUN AS REAL USER)
#---------------------------------------------------------------------------
zenity_u(){
 if [ "$USER" = "root" ] && [ -n "$SUDO_USER" ]; then
  sudo -n -u "$REAL_USER" env DISPLAY="$DISPLAY_VAL" XAUTHORITY="$XAUTH_FILE" GTK_THEME="${GTK_THEME}" zenity "$@" 2>/dev/null
 else
  env DISPLAY="$DISPLAY_VAL" XAUTHORITY="$XAUTH_FILE" GTK_THEME="${GTK_THEME}" zenity "$@" 2>/dev/null
 fi
}
#---------------------------------------------------------------------------
# POPUP
#---------------------------------------------------------------------------
popup_and_act(){
 trap - EXIT INT TERM # Clear inherited global traps in backgrounded subshell
 local answer
 local IP="$1"
 local same_net=0
 local NETCARD="$2"
 local POPUP_LOCK="${TEMP_DIR}/popup.${IP}.lock"
 #
 [ -f "${ISOLATE_MARKER_DIR}/${IP}" ] && return
 lock_acquire "${POPUP_LOCK}" || return
 trap 'lock_release "${POPUP_LOCK}"' EXIT
 same_subnet_on_iface "${IP}" && same_net=1
 if [ "${same_net}" -eq 1 ]; then
  answer="$(zenity_u --question  \
   --title="${TITLE}"            \
   --width=${MENU_WIDTH}         \
   --extra-button="Ignore ${IP}" \
   --extra-button="Change IP"    \
   --extra-button="Go Offline"   \
   --extra-button="Block ${IP}"  \
   --extra-button="Allow ${IP}"  \
   --extra-button="Stop monitoring ${IP}" \
   --ok-label="Isolate ${IP} (${ISOLATE_TIME_SEC}s)" \
   --text="Ping from: ${IP}\nNetcard: ${NETCARD}\n\nSelect action:" \
   --cancel-label="Cancel")"
 else
  answer="$(zenity_u --question  \
   --title="${TITLE}"            \
   --width=${MENU_WIDTH}         \
   --extra-button="Ignore ${IP}" \
   --ok-label="Block ${IP}"      \
   --extra-button="Change IP"    \
   --extra-button="Go Offline"   \
   --extra-button="Allow ${IP}"  \
   --extra-button="Stop monitoring ${IP}" \
   --text="Ping from: ${IP}\nNetcard: ${NETCARD}\n\nSelect action:" \
   --cancel-label="Cancel")"
 fi
 local ret=$?  # Handle Zenity return values.
 if [ $ret -eq 0 ] && [ -z "${answer}" ]; then
  if [ "${same_net}" -eq 1 ]; then
   answer="Isolate ${IP}"
  else
   answer="Block ${IP}"
  fi
 fi
 case "${answer}" in
	"Ignore ${IP}"|"Stop monitoring ${IP}")
		echo "${IP}" >> "${IGNORE_IP_LIST}"
		chmod 600 "${IGNORE_IP_LIST}"
		log_msg "+" "Action: Ignoring/Stopped monitoring ${IP}"
		;;
	"Block ${IP}") # Block all traffic from this IP in the block chain
		sudo -n iptables -A "${BLOCK_CHAIN}" -s "${IP}" -j DROP
		[ "${IP#*:}" != "${IP}" ] && sudo -n ip6tables -A "${BLOCK_CHAIN}" -s "${IP}" -j DROP 2>/dev/null
		echo "${IP}" >> "${IGNORE_IP_LIST}"
		chmod 600 "${IGNORE_IP_LIST}"
		log_msg "+" "Action: Blocked all traffic from ${IP}"
		;;
	"Allow ${IP}") # Allow all traffic from this IP in the allow chain
		sudo -n iptables -A "${ALLOW_CHAIN}" -s "${IP}" -j ACCEPT
		[ "${IP#*:}" != "${IP}" ] && sudo -n ip6tables -A "${ALLOW_CHAIN}" -s "${IP}" -j ACCEPT 2>/dev/null
		sudo -n iptables -A "${ALLOW_CHAIN}" -p icmp -s "${IP}" -j ACCEPT
		echo "${IP}" >> "${IGNORE_IP_LIST}"
		chmod 600 "${IGNORE_IP_LIST}"
		log_msg "+" "Action: Allowed all traffic from ${IP} (including ICMP)"
		;;
	"Isolate ${IP}")
		if [ "${same_net}" -eq 1 ]; then
		 log_msg "+" "Action: Isolating ${IP}"
		 echo "${IP}" >> "${IGNORE_IP_LIST}"
		 chmod 600 "${IGNORE_IP_LIST}"
		 validate_netcard
		 GW=$(get_gateway)
		 # Kill any existing session for this IP before starting a new one.
		 ( sudo -n pkill -KILL -f "[t]imeout.*ettercap.*${IP}" 2>/dev/null ) 2>/dev/null
		 ( sudo -n pkill -INT -f "[e]ttercap.*-M arp.*${IP}" 2>/dev/null ) 2>/dev/null
		 sleep 1
		 TARGET_MAC=$(ip neighbor show "${IP}" | awk '{print $5}' | grep -i '[0-9a-f:]\{17\}' | head -n1)
		 # Create ettercap filter to drop packets and avoid 'Operation not permitted' errors in log
		 FILTER_SRC="${TEMP_DIR}/etter.${IP}.filter"
		 FILTER_BIN="${TEMP_DIR}/etter.${IP}.ef"
		 cat <<EOF > "${FILTER_SRC}"
if (ip.src == '${IP}' || ip.dst == '${IP}') {
    drop();
}
EOF
		 chmod 600 "${FILTER_SRC}"
		 etterfilter "${FILTER_SRC}" -o "${FILTER_BIN}" >/dev/null 2>&1
		 chmod 600 "${FILTER_BIN}"
		 touch "${ISOLATE_MARKER_DIR}/${IP}"
		 chmod 600 "${ISOLATE_MARKER_DIR}/${IP}"
		 (
		  # Clear global traps in the subshell to avoid double cleanup/logging
		  trap - EXIT INT TERM # Suppress job control messages and all output in this subshell
		  set +m
		  exec 2>/dev/null
		  # Subshell cleanup
		  trap 'sudo -n iptables -t raw -D "${ISO_CHAIN_IN}" -s "${IP}" -j DROP 2>/dev/null; \
			sudo -n iptables -D "${ISO_CHAIN_IN}" -s "${IP}" -j DROP 2>/dev/null; \
			sudo -n iptables -D "${ISO_CHAIN_OUT}" -d "${IP}" -j DROP 2>/dev/null; \
			rm -f "${ISOLATE_MARKER_DIR}/${IP}"; exit' INT TERM
		  cleanup(){ :; }
		  sudo -n iptables -t raw -A "${ISO_CHAIN_IN}" -s "${IP}" -j DROP
		  sudo -n iptables -A "${ISO_CHAIN_IN}" -s "${IP}" -j DROP
		  [ -n "${TARGET_MAC}" ] && {
		   sudo -n iptables -t raw -A "${ISO_CHAIN_IN}" -m mac --mac-source "${TARGET_MAC}" -j DROP
		   sudo -n iptables -A "${ISO_CHAIN_IN}" -m mac --mac-source "${TARGET_MAC}" -j DROP
		   sudo -n ip6tables -t raw -A "${ISO_CHAIN_IN}" -m mac --mac-source "${TARGET_MAC}" -j DROP
		   sudo -n ip6tables -A "${ISO_CHAIN_IN}" -m mac --mac-source "${TARGET_MAC}" -j DROP
		  }
		  sudo -n iptables -A "${ISO_CHAIN_OUT}" -d "${IP}" -j DROP
		  log_msg "+" "Starting isolation of ${IP} (MAC: ${TARGET_MAC}, Gateway: ${GW}) on ${NETCARD}"
		  # Use -k 10 (kill-after) to ensure it stops if SIGINT fails.
		  # Suppress stderr to keep console clean of 'killed' messages if already dead.
		  if [ $DEBUG -eq 1 ]; then
		   sudo -n timeout -k 10 -s INT ${ISOLATE_TIME_SEC} ettercap -T -q -F "${FILTER_BIN}" -M arp -i "${NETCARD}" /${IP}// /${GW}// < /dev/null 2>&1 | sudo -n tee -a "${DEBUG_LOG}" >/dev/null
		  else
		   sudo -n timeout -k 10 -s INT ${ISOLATE_TIME_SEC} ettercap -T -q -F "${FILTER_BIN}" -M arp -i "${NETCARD}" /${IP}// /${GW}// < /dev/null >/dev/null 2>&1
		  fi
		  # Cleanup
		  sudo -n iptables -t raw -D "${ISO_CHAIN_IN}" -s "${IP}" -j DROP 2>/dev/null
		  sudo -n iptables -D "${ISO_CHAIN_IN}" -s "${IP}" -j DROP 2>/dev/null
		  [ -n "${TARGET_MAC}" ] && {
		   sudo -n iptables -t raw -D "${ISO_CHAIN_IN}" -m mac --mac-source "${TARGET_MAC}" -j DROP 2>/dev/null
		   sudo -n iptables -D "${ISO_CHAIN_IN}" -m mac --mac-source "${TARGET_MAC}" -j DROP 2>/dev/null
		   sudo -n ip6tables -t raw -D "${ISO_CHAIN_IN}" -m mac --mac-source "${TARGET_MAC}" -j DROP 2>/dev/null
		   sudo -n ip6tables -D "${ISO_CHAIN_IN}" -m mac --mac-source "${TARGET_MAC}" -j DROP 2>/dev/null
		  }
		  sudo -n iptables -D "${ISO_CHAIN_OUT}" -d "${IP}" -j DROP 2>/dev/null
		  sudo rm -f "${FILTER_SRC}" "${FILTER_BIN}"
		  # Remove from ignore list when isolation ends
		  sed -i "/^${IP}$/d" "${IGNORE_IP_LIST}" 2>/dev/null
		  rm -f "${ISOLATE_MARKER_DIR}/${IP}"
		  log_msg "+" "Stopped isolation of ${IP} on ${NETCARD}"
		 ) &
		 disown
		fi
		;;
	"Change IP")
		log_msg "+" "Action: Changing IP on ${NETCARD}"
		validate_netcard
		sudo -n nmcli dev disconnect "${NETCARD}"
		sudo -n macchanger -r "${NETCARD}"
		sudo -n nmcli dev connect "${NETCARD}"
		;;
	"Go Offline")
		log_msg "+" "Action: Going Offline"
		sudo -n nmcli networking off
		;;
 esac
}
#---------------------------------------------------------------------------
# MAIN
#---------------------------------------------------------------------------
main(){
 check_sudo
 log_msg "+" "ICMP Watcher starting..."
 # Cleanup any stale processes from previous runs.
 ( sudo -n pkill -KILL -f "[t]imeout.*ettercap" 2>/dev/null ) 2>/dev/null
 ( sudo -n pkill -INT -f "[e]ttercap.*-M arp" 2>/dev/null ) 2>/dev/null
 # Enable IP forwarding for MITM and ENSURE local ICMP responses are enabled
 log_msg "+" "Enabling IP forwarding and ICMP responses..."
 echo 1 | sudo -n tee /proc/sys/net/ipv4/ip_forward >/dev/null 2>&1
 echo 0 | sudo -n tee /proc/sys/net/ipv4/icmp_echo_ignore_all >/dev/null 2>&1
 log_msg "+" "Initializing firewall and detection..."
 init_firewall
 init_detection
 pick_gtk_theme
 log_msg "+" "Monitoring ${LOCAL_IPS} for ICMP pings (NFLOG group 42)..."
 # Start ulogd
 ULOGD_REDIR="/dev/null"
 if [ "${DEBUG:-0}" -eq 1 ]; then
  sudo -n touch "${DEBUG_LOG}" 2>/dev/null
  sudo -n chmod 0640 "${DEBUG_LOG}" 2>/dev/null
  ULOGD_REDIR="${DEBUG_LOG}"
 fi
 sudo -n bash -c "ulogd -c '${ULOGD_CONF}' -v 2>> '${ULOGD_REDIR}'" | awk "${ULOGD_AWK_SCRIPT}" | \
 (
  trap - EXIT INT TERM; while read -r IFACE SRC DST; do
  [ "$DEBUG" -eq 1 ] && printf "DEBUG: Received from parser: IFACE=%s SRC=%s DST=%s\n" "$IFACE" "$SRC" "$DST" >&2
  [ -n "${SRC}" ] || continue
  if [ "${INCLUDE_LOCAL}" != "1" ]; then
   [ "${IFACE}" = "lo" ] && continue
   ip_is_local "${SRC}" && continue
  fi
  should_ignore_ip "${SRC}" && continue
  [ -f "${ISOLATE_MARKER_DIR}/${SRC}" ] && continue
  log_msg "!" "Ping detected from ${SRC} on ${IFACE}"
  popup_and_act "${SRC}" "${IFACE}" &
  disown
  done
 )
}
trap cleanup EXIT INT TERM
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
 main "$@"
fi
#---------------------------------------------------------------------------
# END
#---------------------------------------------------------------------------
