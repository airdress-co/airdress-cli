#!/usr/bin/env bash
# The shell host never crosses a user boundary (D-15): nothing in the
# `airdress-shell-host` crate calls setuid, setgid, initgroups or their
# relatives, sets a child's uid, gid or groups, or runs sudo, su or doas.
#
# Checked on the crate's own compiled objects, not the whole binary: the
# standard library's process spawning references setuid/setgid/setgroups
# behind `CommandExt::uid/gid/groups`, which every binary that starts a
# process links, and which this crate never calls (the source check below).
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

cargo build -q --release -p airdress-shell-host
rlib=$(ls -t target/release/deps/libairdress_shell_host-*.rlib | head -1)
symbols='\b(setuid|setgid|seteuid|setegid|setreuid|setregid|setresuid|setresgid|initgroups|setgroups)\b'
fail=0
if nm "$rlib" 2>/dev/null | grep -E " U .*${symbols}"; then
    echo "shell host: the crate references a user-switching call" >&2
    fail=1
fi
if git grep -nE '\.(uid|gid|groups)\([^)]|"(sudo|su|doas)"|\b(setuid|setgid|initgroups)\(' -- crates/airdress-shell-host/src; then
    echo "shell host: the source switches user, or runs something that does" >&2
    fail=1
fi
[[ $fail -eq 0 ]] && echo "shell host: no user switching (checked $(basename "$rlib"))"
exit "$fail"
