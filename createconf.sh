#!/bin/sh

create_exa_config() {
	local _localip=$1 _localas=$2 _localid=$3
	local _peerip=$4 _peeras=$5 _mrtfile=$6
	local _file="exa-$_localip.conf"

	cat > $_file <<EOF
process injector {
	run /usr/local/bin/mrt4exabgp -n "$_localip" "$_mrtfile";
	encoder text;
}

neighbor $_peerip {
	router-id $_localid;
	peer-as $_peeras;
	local-address $_localip;
	local-as $_localas;
	group-updates;
	adj-rib-in false;

	api {
		processes [ injector ];
	}
}
EOF
}

create_setup() {
	local _ip=$1 _iface=$2 _af="inet" _plen=32

	if [ "$_ip" != "${_ip##*:}" ]; then
		_af="inet6"
		_plen=128
	fi

	cat >> setup.sh <<EOF
ifconfig $_iface $_af alias $_ip/$_plen
EOF
}

usage() {
	echo "usage: ${0##*/} [-4 ip] [-6 ip6] -a rs-as -i iface mrtfile" >&2
	exit 1
}

while getopts "4:6:a:i:" opt; do
	case $opt in
	4)	RSIP="$OPTARG";;
	6)	RSIP6="$OPTARG";;
	a)	RSAS="$OPTARG";;
	i)	IFACE="$OPTARG";;
	*)	usage;;
	esac
done
shift $((OPTIND-1))
mrtfile="$1"

[ -z "$RSAS" -o -z "$IFACE" -o \! -f "$mrtfile" ] && usage


cat > setup.sh <<EOF
#!/bin/sh
# created with ${0##*/} -4 $RSIP -6 $RSIP6 -a $RSAS -i $IFACE
set -e

EOF

while read ip as bgpid; do
	if [ "$ip" = "${ip##*:}" ]; then
		rsip="$RSIP"
	else
		rsip="$RSIP6"
	fi
	if [ "$as" = 0 -o "$ip" = "0.0.0.0" ]; then
		echo "ignoring $ip, ASnum is zero or IP is 0.0.0.0" >&2
		continue
	fi
	if [ X = X"$rsip" ]; then
		echo "ignoring $ip, no matching route server IP" >&2
		continue
	fi
	create_exa_config "$ip" "$as" "$bgpid" "$rsip" "$RSAS" "$mrtfile"
	create_setup "$ip" "$IFACE"
done
