#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

ksft_skip=4
ret=0

ACTIVE=/proc/vpsadminos/kernfs_filter/active
REPLACE=/proc/vpsadminos/kernfs_filter/replace
STATS=/proc/vpsadminos/kernfs_filter/stats
SYSFS_TARGET=/sys/devices/system/cpu/cpu0
PROC_TARGET=/proc/diskstats
TRANSACTION_HELPER="$(dirname "$0")/kernfs_filter_transaction"
DIR_VIEW_HELPER="$(dirname "$0")/kernfs_filter_dir_view"

TMPDIR=
BACKUP=
EMPTY_POLICY=
HIDE_SYSFS_POLICY=
HIDE_PROC_POLICY=
HIDE_DYNAMIC_PROC_POLICY=

skip()
{
	echo "skip: $*" >&2
	exit $ksft_skip
}

fail()
{
	echo "not ok: $*" >&2
	ret=1
}

restore_policy()
{
	if [ -n "$BACKUP" ] && [ -f "$BACKUP" ]; then
		"$TRANSACTION_HELPER" install "$REPLACE" "$BACKUP" >/dev/null 2>&1 ||
			echo "warning: failed to restore active kernfs-filter policy" >&2
	fi

	if [ -n "$TMPDIR" ] && [ -d "$TMPDIR" ]; then
		rm -rf "$TMPDIR"
	fi
}

require_root_and_feature()
{
	if [ "$(id -u)" -ne 0 ]; then
		skip "must run as root"
	fi

	if [ ! -r "$ACTIVE" ] || [ ! -w "$REPLACE" ] || [ ! -r "$STATS" ]; then
		skip "kernfs-filter control plane not present"
	fi
	if [ ! -x "$TRANSACTION_HELPER" ]; then
		skip "kernfs-filter transaction helper not built"
	fi
	if [ ! -x "$DIR_VIEW_HELPER" ]; then
		skip "kernfs-filter directory-view helper not built"
	fi

	command -v unshare >/dev/null 2>&1 || skip "unshare command missing"

	if [ ! -e "$SYSFS_TARGET" ]; then
		skip "required sysfs target $SYSFS_TARGET missing"
	fi

	if [ ! -e "$PROC_TARGET" ]; then
		skip "required proc target $PROC_TARGET missing"
	fi

	unshare -Ur true >/dev/null 2>&1 ||
		skip "cannot create a restricted user namespace"
}

make_policy_files()
{
	TMPDIR=$(mktemp -d /tmp/vpsa-kernfs-filter-selftest.XXXXXX) || exit 1
	BACKUP=$TMPDIR/original.policy
	EMPTY_POLICY=$TMPDIR/empty.policy
	HIDE_SYSFS_POLICY=$TMPDIR/hide-sysfs.policy
	HIDE_PROC_POLICY=$TMPDIR/hide-proc.policy
	HIDE_DYNAMIC_PROC_POLICY=$TMPDIR/hide-dynamic-proc.policy

	cat "$ACTIVE" > "$BACKUP" || exit 1

	cat > "$EMPTY_POLICY" <<'POLICY'
version 1
scope noninit-userns
POLICY

	cat > "$HIDE_SYSFS_POLICY" <<'POLICY'
version 1
scope noninit-userns
sysfs hide any /devices/system/cpu/cpu0
POLICY

	cat > "$HIDE_PROC_POLICY" <<'POLICY'
version 1
scope noninit-userns
proc hide any /diskstats
POLICY

	cat > "$HIDE_DYNAMIC_PROC_POLICY" <<'POLICY'
version 1
scope noninit-userns
proc hide any /*/fd/*
proc hide any /*/fdinfo/*
proc hide any /*/map_files/*
proc hide any /*/ns/*
POLICY
}

install_policy()
{
	policy=$1

	if ! "$TRANSACTION_HELPER" install "$REPLACE" "$policy"; then
		fail "failed to install policy from $policy"
		return 1
	fi

	return 0
}

assert_host_exists()
{
	label=$1
	path=$2

	if [ ! -e "$path" ]; then
		fail "$label: host cannot see $path"
	fi
}

assert_restricted_exists()
{
	label=$1
	path=$2

	if ! unshare -Ur sh -c 'test -e "$1"' sh "$path"; then
		fail "$label: restricted task cannot see $path"
	fi
}

assert_restricted_missing()
{
	label=$1
	path=$2

	if unshare -Ur sh -c 'test -e "$1"' sh "$path"; then
		fail "$label: restricted task unexpectedly sees $path"
	fi
}

assert_restricted_dynamic_proc_entries()
{
	label=$1
	expected=$2

	if ! unshare -Ur sh -s -- "$expected" <<'CHILD'
expected=$1
exec 9</dev/null

case "$expected" in
present)
	test -e /proc/self/fd/9 || exit 1
	test -e /proc/self/fdinfo/9 || exit 1
	test -e /proc/self/ns/user || exit 1

	set -- /proc/self/fd/*
	test "$1" != '/proc/self/fd/*' || exit 1
	set -- /proc/self/fdinfo/*
	test "$1" != '/proc/self/fdinfo/*' || exit 1
	set -- /proc/self/map_files/*
	test "$1" != '/proc/self/map_files/*' || exit 1
	set -- /proc/self/ns/*
	test "$1" != '/proc/self/ns/*' || exit 1
	;;
hidden)
	test ! -e /proc/self/fd/9 || exit 1
	test ! -e /proc/self/fdinfo/9 || exit 1
	test ! -e /proc/self/ns/user || exit 1

	set -- /proc/self/fd/*
	test "$1" = '/proc/self/fd/*' || exit 1
	set -- /proc/self/fdinfo/*
	test "$1" = '/proc/self/fdinfo/*' || exit 1
	set -- /proc/self/map_files/*
	test "$1" = '/proc/self/map_files/*' || exit 1
	set -- /proc/self/ns/*
	test "$1" = '/proc/self/ns/*' || exit 1
	;;
*)
	exit 1
	;;
esac
CHILD
	then
		fail "$label: expected dynamic proc entries to be $expected"
	fi
}

run_restricted_dynamic_dir_reload_case()
{
	label=$1
	before_policy=$2
	after_policy=$3
	expect_readdir=$4
	expect_lookup=$5
	ready=$TMPDIR/${label}.ready
	go=$TMPDIR/${label}.go
	out=$TMPDIR/${label}.out
	pid=
	readdir_result=
	lookup_result=

	rm -f "$ready" "$go" "$out"
	mkfifo "$ready" "$go" || {
		fail "$label: failed to create coordination fifos"
		return
	}

	install_policy "$before_policy" || {
		rm -f "$ready" "$go" "$out"
		return
	}

	unshare -Ur "$DIR_VIEW_HELPER" \
		/proc/self/fd 9 /proc/self/fd/9 "$ready" "$go" \
		> "$out" 2>&1 &
	pid=$!

	if ! IFS= read -r _ < "$ready"; then
		fail "$label: restricted helper did not open its directory"
		kill "$pid" >/dev/null 2>&1 || true
		wait "$pid" >/dev/null 2>&1 || true
		rm -f "$ready" "$go" "$out"
		return
	fi

	install_policy "$after_policy" || {
		kill "$pid" >/dev/null 2>&1 || true
		wait "$pid" >/dev/null 2>&1 || true
		rm -f "$ready" "$go" "$out"
		return
	}

	printf 'go\n' > "$go"

	if ! wait "$pid"; then
		fail "$label: restricted helper exited non-zero"
	fi

	readdir_result=$(grep '^readdir=' "$out" | tail -n 1 | cut -d= -f2)
	lookup_result=$(grep '^lookup=' "$out" | tail -n 1 | cut -d= -f2)

	if [ "$readdir_result" != "$expect_readdir" ]; then
		fail "$label: expected readdir=$expect_readdir, got ${readdir_result:-<unset>}"
	fi

	if [ "$lookup_result" != "$expect_lookup" ]; then
		fail "$label: expected lookup=$expect_lookup, got ${lookup_result:-<unset>}"
	fi

	rm -f "$ready" "$go" "$out"
}

run_restricted_reload_case()
{
	label=$1
	before_policy=$2
	after_policy=$3
	path=$4
	expect_first=$5
	expect_second=$6
	ready=$TMPDIR/${label}.ready
	go=$TMPDIR/${label}.go
	out=$TMPDIR/${label}.out
	pid=
	first=
	second=

	rm -f "$ready" "$go" "$out"
	mkfifo "$ready" "$go" || {
		fail "$label: failed to create coordination fifos"
		return
	}

	install_policy "$before_policy" || {
		rm -f "$ready" "$go" "$out"
		return
	}

	unshare -Ur sh -s -- "$path" "$ready" "$go" > "$out" 2>&1 <<'CHILD' &
path=$1
ready=$2
go=$3

if test -e "$path"; then
	echo first=present
else
	echo first=missing
fi

echo ready > "$ready"
IFS= read -r _ < "$go"

if test -e "$path"; then
	echo second=present
else
	echo second=missing
fi
CHILD
	pid=$!

	if ! IFS= read -r _ < "$ready"; then
		fail "$label: restricted helper did not reach the rendezvous point"
		kill "$pid" >/dev/null 2>&1 || true
		wait "$pid" >/dev/null 2>&1 || true
		rm -f "$ready" "$go" "$out"
		return
	fi

	install_policy "$after_policy" || {
		kill "$pid" >/dev/null 2>&1 || true
		wait "$pid" >/dev/null 2>&1 || true
		rm -f "$ready" "$go" "$out"
		return
	}

	printf 'go\n' > "$go"

	if ! wait "$pid"; then
		fail "$label: restricted helper exited non-zero"
	fi

	first=$(grep '^first=' "$out" | tail -n 1 | cut -d= -f2)
	second=$(grep '^second=' "$out" | tail -n 1 | cut -d= -f2)

	if [ "$first" != "$expect_first" ]; then
		fail "$label: expected first=$expect_first, got ${first:-<unset>}"
	fi

	if [ "$second" != "$expect_second" ]; then
		fail "$label: expected second=$expect_second, got ${second:-<unset>}"
	fi

	rm -f "$ready" "$go" "$out"
}

require_root_and_feature
make_policy_files
trap restore_policy EXIT HUP INT TERM

install_policy "$EMPTY_POLICY" || exit 1
if ! "$TRANSACTION_HELPER" "$REPLACE" "$ACTIVE" "$STATS" "$EMPTY_POLICY"; then
	fail "kernfs-filter replacement transaction checks failed"
fi
assert_restricted_exists "empty-policy sysfs baseline" "$SYSFS_TARGET"
assert_restricted_exists "empty-policy proc baseline" "$PROC_TARGET"
assert_restricted_dynamic_proc_entries \
	"empty-policy dynamic proc baseline" \
	present

install_policy "$HIDE_DYNAMIC_PROC_POLICY" || exit 1
assert_restricted_dynamic_proc_entries \
	"dynamic proc lookup and readdir filtering" \
	hidden
assert_host_exists "host fd view remains unaffected" /proc/self/fd/0
assert_host_exists "host namespace view remains unaffected" /proc/self/ns/user

run_restricted_dynamic_dir_reload_case \
	dynamic_proc_visible_to_hidden \
	"$EMPTY_POLICY" \
	"$HIDE_DYNAMIC_PROC_POLICY" \
	present \
	missing

run_restricted_dynamic_dir_reload_case \
	dynamic_proc_hidden_to_visible \
	"$HIDE_DYNAMIC_PROC_POLICY" \
	"$EMPTY_POLICY" \
	missing \
	present

install_policy "$HIDE_SYSFS_POLICY" || exit 1
assert_restricted_missing "sysfs hide applies to restricted tasks" "$SYSFS_TARGET"
assert_host_exists "host remains unaffected after restricted sysfs miss" "$SYSFS_TARGET"

install_policy "$HIDE_PROC_POLICY" || exit 1
assert_restricted_missing "proc hide applies to restricted tasks" "$PROC_TARGET"
assert_host_exists "host remains unaffected after restricted proc miss" "$PROC_TARGET"

run_restricted_reload_case \
	sysfs_visible_to_hidden \
	"$EMPTY_POLICY" \
	"$HIDE_SYSFS_POLICY" \
	"$SYSFS_TARGET" \
	present \
	missing

run_restricted_reload_case \
	sysfs_hidden_to_visible \
	"$HIDE_SYSFS_POLICY" \
	"$EMPTY_POLICY" \
	"$SYSFS_TARGET" \
	missing \
	present

run_restricted_reload_case \
	proc_visible_to_hidden \
	"$EMPTY_POLICY" \
	"$HIDE_PROC_POLICY" \
	"$PROC_TARGET" \
	present \
	missing

run_restricted_reload_case \
	proc_hidden_to_visible \
	"$HIDE_PROC_POLICY" \
	"$EMPTY_POLICY" \
	"$PROC_TARGET" \
	missing \
	present

exit $ret
