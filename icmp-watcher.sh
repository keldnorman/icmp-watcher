#!/bin/bash
DEBUG=${DEBUG:-0}
DEBUG_LOG="/tmp/icmp-watcher.debug.log"

if [ "$DEBUG" -eq 1 ]; then
    echo "--- Script started at $(date) ---" > "$DEBUG_LOG"
    exec > >(tee -a "$DEBUG_LOG") 2>&1
    set -x
else
    set +x
fi

if [ -t 1 ]; then clear; fi
#---------------------------------------------------------------------------
# VARIABLES
#---------------------------------------------------------------------------
ORIG_IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)
ORIG_ICMP_IGNORE=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_all 2>/dev/null || echo 0)
IGNORE_IP_LIST="/tmp/icmp.monitor.ignore.ip.list"
ISOLATE_MARKER_DIR="/tmp/icmp.monitor.isolating"
INCLUDE_LOCAL="${INCLUDE_LOCAL:-0}"
LOCKFILE="/tmp/icmp.monitor.lock.pid"
ISOLATE_TIME_SEC=300
WIDTH=520
TITLE="Sonar Ping Detected"
ISO_CHAIN_IN="ICMP_WATCHER_ISO_IN"
ISO_CHAIN_OUT="ICMP_WATCHER_ISO_OUT"

#---------------------------------------------------------------------------
# USER / DISPLAY CONTEXT
#---------------------------------------------------------------------------
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME="$(getent passwd "$REAL_USER" | awk -F: '{print $6}')"
DISPLAY_VAL="${DISPLAY:-:0.0}"
XAUTH_FILE="${XAUTHORITY:-${REAL_HOME}/.Xauthority}"
#---------------------------------------------------------------------------
# DEPENDENCY CHECK
#---------------------------------------------------------------------------
check_sudo(){
	if ! sudo -n true 2>/dev/null; then
		zenity --error --text="This script requires passwordless sudo for 'norman' user." --title="Permission Error" 2>/dev/null
		echo "ERROR: Passwordless sudo is required." >&2
		exit 1
	fi
}
ensure_pkg(){
	local cmd="$1"
	local pkg="$2"
	if ! command -v "$cmd" >/dev/null 2>&1; then
		sudo -n apt-get update -qq && sudo -n apt-get install -y "$pkg" || exit 1
	fi
}
ensure_pkg tcpdump tcpdump
ensure_pkg zenity zenity
ensure_pkg nmcli network-manager
ensure_pkg iptables iptables
ensure_pkg macchanger macchanger
ensure_pkg ettercap ettercap-text-only
ensure_pkg etterfilter ettercap-text-only
ensure_pkg timeout coreutils
ensure_pkg ip iproute2
ensure_pkg awk gawk
ensure_pkg sed sed
ensure_pkg grep grep
ensure_pkg cut coreutils
ensure_pkg tr coreutils
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
build_local_ip_map(){
	LOCAL_IPS="$(ip -o -4 addr show | awk '{print $4}' | cut -d/ -f1 | tr '\n' ' ')"
}
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
	if [ -f "${LOCKFILE}" ]; then
		oldpid="$(cat "${LOCKFILE}" 2>/dev/null)"
		if [ -n "${oldpid}" ] && kill -0 "${oldpid}" 2>/dev/null; then
			return 1
		fi
		rm -f "${LOCKFILE}"
	fi
	echo $$ > "${LOCKFILE}" || return 1
	return 0
}
lock_release(){
	rm -f "${LOCKFILE}" 2>/dev/null
}
#---------------------------------------------------------------------------
# IPTABLES ISOLATION CHAIN
#---------------------------------------------------------------------------
remove_iso_chain(){
    for cmd in iptables ip6tables; do
        # Detach from all possible hooks
        for hook in INPUT FORWARD PREROUTING; do
            sudo -n $cmd -D $hook -j "${ISO_CHAIN_IN}" 2>/dev/null
            sudo -n $cmd -t raw -D $hook -j "${ISO_CHAIN_IN}" 2>/dev/null
        done
        sudo -n $cmd -D OUTPUT -j "${ISO_CHAIN_OUT}" 2>/dev/null

        # Detach from legacy hooks if any
        sudo -n $cmd -D INPUT -j "ICMP_WATCHER_ISOLATE" 2>/dev/null
        sudo -n $cmd -D FORWARD -j "ICMP_WATCHER_ISOLATE" 2>/dev/null
        sudo -n $cmd -D OUTPUT -j "ICMP_WATCHER_ISOLATE" 2>/dev/null
        sudo -n $cmd -t raw -D PREROUTING -j "ICMP_WATCHER_ISOLATE" 2>/dev/null

        # Delete the chains
        for chain in "${ISO_CHAIN_IN}" "${ISO_CHAIN_OUT}" "ICMP_WATCHER_ISOLATE"; do
            sudo -n $cmd -F "${chain}" 2>/dev/null
            sudo -n $cmd -X "${chain}" 2>/dev/null
            sudo -n $cmd -t raw -F "${chain}" 2>/dev/null
            sudo -n $cmd -t raw -X "${chain}" 2>/dev/null
        done
    done
}
init_iso_chain(){
    remove_iso_chain
    sudo rm -f "${IGNORE_IP_LIST}"
    mkdir -p "${ISOLATE_MARKER_DIR}"
    for cmd in iptables ip6tables; do
        # Inbound chain for PREROUTING, INPUT, FORWARD (where MAC matching is allowed)
        sudo -n $cmd -N "${ISO_CHAIN_IN}"
        sudo -n $cmd -t raw -N "${ISO_CHAIN_IN}"
        sudo -n $cmd -I INPUT 1 -j "${ISO_CHAIN_IN}"
        sudo -n $cmd -I FORWARD 1 -j "${ISO_CHAIN_IN}"
        sudo -n $cmd -t raw -I PREROUTING 1 -j "${ISO_CHAIN_IN}"

        # Outbound chain for OUTPUT (where MAC matching is NOT allowed)
        sudo -n $cmd -N "${ISO_CHAIN_OUT}"
        sudo -n $cmd -I OUTPUT 1 -j "${ISO_CHAIN_OUT}"
    done
}
cleanup(){
	sudo -n pkill -INT -f "ettercap.*-M arp" 2>/dev/null
	remove_iso_chain
	sudo -n rm -rf "${ISOLATE_MARKER_DIR}" 2>/dev/null
	sudo -n rm -f "${IGNORE_IP_LIST}" 2>/dev/null
	sudo -n rm -f /tmp/etter.*.filter /tmp/etter.*.ef 2>/dev/null
	[ -n "${ORIG_IP_FORWARD}" ] && echo "${ORIG_IP_FORWARD}" | sudo -n tee /proc/sys/net/ipv4/ip_forward >/dev/null 2>&1
	[ -n "${ORIG_ICMP_IGNORE}" ] && echo "${ORIG_ICMP_IGNORE}" | sudo -n tee /proc/sys/net/ipv4/icmp_echo_ignore_all >/dev/null 2>&1
	lock_release
	exit 0
}
trap cleanup EXIT INT TERM
#---------------------------------------------------------------------------
# ZENITY WRAPPER (RUN AS REAL USER)
#---------------------------------------------------------------------------
zenity_u(){
	sudo -n -u "$REAL_USER" env DISPLAY="$DISPLAY_VAL" XAUTHORITY="$XAUTH_FILE" GTK_THEME="${GTK_THEME}" zenity "$@"
}
#---------------------------------------------------------------------------
# POPUP
#---------------------------------------------------------------------------
popup_and_act(){
	[ -f "${ISOLATE_MARKER_DIR}/${IP}" ] && return
	lock_acquire || return
	trap 'lock_release' RETURN

	local same_net=0
	same_subnet_on_iface "${IP}" && same_net=1

	if [ "${same_net}" -eq 1 ]; then
		answer="$(zenity_u --question \
			--title="${TITLE}" \
			--width=${WIDTH} \
			--text="Ping from: ${IP}\nNetcard: ${NETCARD}\n\nSelect action:" \
			--extra-button="Isolate ${IP}" \
			--extra-button="Block ${IP}" \
			--extra-button="Stop monitoring ${IP}" \
			--extra-button="Ignore" \
			--extra-button="Change IP" \
			--ok-label="Go Offline" \
			--cancel-label="Cancel")"
	else
		answer="$(zenity_u --question \
			--title="${TITLE}" \
			--width=${WIDTH} \
			--text="Ping from: ${IP}\nNetcard: ${NETCARD}\n\nSelect action:" \
			--extra-button="Block ${IP}" \
			--extra-button="Stop monitoring ${IP}" \
			--extra-button="Change IP" \
			--ok-label="Go Offline" \
			--cancel-label="Cancel")"
	fi

	# Handle OK button (Zenity returns exit code 0 and empty stdout for OK)
	if [ $? -eq 0 ] && [ -z "${answer}" ]; then
		answer="Go Offline"
	fi

	case "${answer}" in
		"Ignore")
			[ "${same_net}" -eq 1 ] && echo "${IP}" | sudo -n tee -a "${IGNORE_IP_LIST}" >/dev/null
			;;
		"Block ${IP}")
			validate_netcard
			sudo -n iptables -C INPUT -i "${NETCARD}" -s "${IP}" -j DROP 2>/dev/null || \
			sudo -n iptables -I INPUT 1 -i "${NETCARD}" -s "${IP}" -j DROP
			;;
		"Isolate ${IP}")
			if [ "${same_net}" -eq 1 ]; then
				validate_netcard
				GW=$(get_gateway)
				sudo -n pkill -INT -f "ettercap.*-M arp.*${IP}" 2>/dev/null
				TARGET_MAC=$(ip neighbor show "${IP}" | awk '{print $5}' | grep -i '[0-9a-f:]\{17\}' | head -n1)

				# Create ettercap filter to drop packets and avoid 'Operation not permitted' errors in log
				FILTER_SRC="/tmp/etter.${IP}.filter"
				FILTER_BIN="/tmp/etter.${IP}.ef"
				cat <<EOF > "${FILTER_SRC}"
if (ip.src == '${IP}' || ip.dst == '${IP}') {
    drop();
}
EOF
				sudo -n etterfilter "${FILTER_SRC}" -o "${FILTER_BIN}" >/dev/null 2>&1

				touch "${ISOLATE_MARKER_DIR}/${IP}"
				(
					trap - EXIT INT TERM
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

					echo "<5>icmp-watcher: Starting isolation of ${IP} (MAC: ${TARGET_MAC}, Gateway: ${GW}) on ${NETCARD}" | sudo -n tee /dev/kmsg >/dev/null 2>&1

					# Run ettercap with the filter (-F) to prevent forwarding blocked traffic
					if [ "$DEBUG" -eq 1 ]; then
						sudo -n timeout -s INT ${ISOLATE_TIME_SEC} ettercap -T -q -F "${FILTER_BIN}" -M arp -i "${NETCARD}" /${IP}// /${GW}// < /dev/null >> "$DEBUG_LOG" 2>&1
					else
						sudo -n timeout -s INT ${ISOLATE_TIME_SEC} ettercap -T -q -F "${FILTER_BIN}" -M arp -i "${NETCARD}" /${IP}// /${GW}// < /dev/null >/dev/null 2>&1
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
					rm -f "${ISOLATE_MARKER_DIR}/${IP}"
					echo "<5>icmp-watcher: Stopped isolation of ${IP} on ${NETCARD}" | sudo -n tee /dev/kmsg >/dev/null 2>&1
				) &
			fi
			;;
		"Change IP")
			validate_netcard
			sudo -n nmcli dev disconnect "${NETCARD}"
			sudo -n macchanger -r "${NETCARD}"
			sudo -n nmcli dev connect "${NETCARD}"
			;;
		"Go Offline")
			sudo -n nmcli networking off
			;;
		"Stop monitoring ${IP}")
			exit 0
			;;
	esac
}

#---------------------------------------------------------------------------
# MAIN
#---------------------------------------------------------------------------
check_sudo
# Enable IP forwarding for MITM and disable local ICMP responses for stealth
echo 1 | sudo -n tee /proc/sys/net/ipv4/ip_forward >/dev/null 2>&1
echo 1 | sudo -n tee /proc/sys/net/ipv4/icmp_echo_ignore_all >/dev/null 2>&1
init_iso_chain
pick_gtk_theme
build_local_ip_map
sudo -n tcpdump -i any -l -n -q 'icmp and icmp[icmptype]==icmp-echo' 2>/dev/null | while IFS= read -r line; do
	read IFACE DIR SRC DST <<EOF
$(echo "$line" | awk '{
if (index($1,":")>0){iface=$2;dir=$3}else{iface=$1;dir=$2}
for(i=1;i<=NF;i++) if($i=="IP"){src=$(i+1);dst=$(i+3);break}
sub(/\.$/,"",src); sub(/:$/,"",dst)
print iface,dir,src,dst
}')
EOF
	[ "${DIR}" = "In" ] || continue
	if [ "${INCLUDE_LOCAL}" != "1" ]; then
		[ "${IFACE}" = "lo" ] && continue
		ip_is_local "${SRC}" && continue
	fi
	should_ignore_ip "${SRC}" && continue
	IP="${SRC}"
	NETCARD="${IFACE}"
	popup_and_act
done
#---------------------------------------------------------------------------
# END
#---------------------------------------------------------------------------
