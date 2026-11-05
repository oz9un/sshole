#!/bin/sh
# am i an *sshole?  run as root on the host you're worried about.
# exits 0 = exposed, 1 = not exposed, 2 = can't tell
# https://sshhole.com

# alpine ships two flavours; /etc/conf.d/sshd picks one
flavor=$(grep -E '^sshd_flavor=' /etc/conf.d/sshd 2>/dev/null | cut -d= -f2 | tr -d '"')
sshd=""
for c in "/usr/sbin/sshd${flavor:+.$flavor}" /usr/sbin/sshd /usr/local/sbin/sshd "$(command -v sshd 2>/dev/null)"; do
  [ -n "$c" ] && [ -x "$c" ] && { sshd=$c; break; }
done
[ -z "$sshd" ] && { echo "no sshd here. you're fine."; exit 1; }
# since 10.0 the password check lives in sshd-session / sshd-auth, not the listener
suffix=${sshd#/usr/sbin/sshd}
auth_bins=$(ls /usr/lib/ssh/sshd-auth$suffix /usr/lib/ssh/sshd-session$suffix /usr/lib/openssh/sshd-auth /usr/lib/openssh/sshd-session /usr/libexec/openssh/sshd-auth /usr/libexec/openssh/sshd-session /usr/libexec/sshd-auth /usr/libexec/sshd-session 2>/dev/null)
bins="$sshd $auth_bins"

say() { printf '%-28s %s\n' "$1" "$2"; }
exposed=1 unsure=0

# 1. musl?
if ls /lib/ld-musl-*.so.1 >/dev/null 2>&1 || grep -qa 'ld-musl' "$sshd" 2>/dev/null; then
  say "libc" "musl"
  musl=1
else
  say "libc" "not musl (glibc, uclibc, bsd...)"
  musl=0
fi

# 2. version
ver=$("$sshd" -V 2>&1 | head -1)
say "sshd" "$ver"
case "$ver" in
  *OpenSSH_10.6p2*|*OpenSSH_10.[7-9]*|*OpenSSH_1[1-9]*) fixed=1 ;;
  *OpenSSH_*) fixed=0 ;;
  *) fixed=0; unsure=1 ;;
esac
# distros backport without bumping the upstream version. alpine bumps only the pkgrel,
# so sshd -V on a patched 3.22 still prints OpenSSH_10.0p2. ask apk instead.
if [ $fixed = 0 ] && command -v apk >/dev/null 2>&1 && [ -f /etc/alpine-release ]; then
  inst=$(apk info -v 2>/dev/null | grep -E '^openssh-server(-pam)?-[0-9]' | head -1 | sed -E 's/^openssh-server(-pam)?-//')
  case "$(cut -d. -f1,2 /etc/alpine-release)" in
    3.16) need=9.0_p1-r6   ;; 3.17) need=9.1_p1-r7  ;; 3.18) need=9.3_p2-r4 ;;
    3.19) need=9.6_p1-r3   ;; 3.20) need=9.7_p1-r6  ;; 3.21) need=9.9_p2-r1 ;;
    3.22) need=10.0_p1-r11 ;; 3.23) need=10.2_p1-r1 ;; 3.24) need=10.3_p1-r2 ;;
    *) need= ;;
  esac
  if [ -n "$inst" ] && [ -n "$need" ]; then
    say "openssh-server pkg" "$inst (fixed: $need)"
    if [ "$(apk version -t "$inst" "$need")" != "<" ]; then fixed=1; fi
  fi
fi

# 3. pam?
pam_built=0
for b in $bins; do
  if ldd "$b" 2>/dev/null | grep -q libpam || grep -qa 'libpam\.so' "$b" 2>/dev/null; then pam_built=1; fi
done
cfg=$("$sshd" -T 2>/dev/null)
[ -z "$cfg" ] && cfg=$("$sshd" -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null)
if [ -z "$cfg" ]; then  # no host keys yet (fresh container): read the config file instead
  f=/etc/ssh/sshd_config
  pa=$(grep -hiE '^[[:space:]]*PasswordAuthentication[[:space:]]' $f /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -1 | awk '{print tolower($2)}')
  up=$(grep -hiE '^[[:space:]]*UsePAM[[:space:]]' $f /etc/ssh/sshd_config.d/*.conf 2>/dev/null | tail -1 | awk '{print tolower($2)}')
  cfg="passwordauthentication ${pa:-yes}
usepam ${up:-no}"
  unsure=1
fi
usepam=$(printf '%s\n' "$cfg" | awk '$1=="usepam"{print $2}')
pwauth=$(printf '%s\n' "$cfg" | awk '$1=="passwordauthentication"{print $2}')
if [ $pam_built = 1 ] && [ "$usepam" = yes ]; then
  say "pam" "built in and on"
  pam=1
else
  say "pam" "off ($( [ $pam_built = 1 ] && echo 'built in, UsePAM no' || echo 'not built in'))"
  pam=0
fi
say "PasswordAuthentication" "${pwauth:-unknown}"

# 4. targets: accounts with exactly "*"
stars=$(awk -F: '$2=="*"{print $1}' /etc/shadow 2>/dev/null | tr '\n' ' ')
pstars=$(awk -F: '$2=="*"{print $1}' /etc/passwd 2>/dev/null | tr '\n' ' ')
targets="$stars$pstars"
say "accounts with '*'" "${targets:-none}"
# directory users via nss (nslcd/winbind/sssd) all look like "*" on musl
if grep -qE '^passwd:.*(ldap|winbind|sss)' /etc/nsswitch.conf 2>/dev/null; then
  say "directory users" "yes (nsswitch) - every one of them is a target"
  targets="$targets directory-users"
fi

# 5. donor: a local $5$/$6$ hash
donor=$(awk -F: '$2 ~ /^\$[56]\$/{print $1; exit}' /etc/shadow 2>/dev/null)
if [ -n "$donor" ]; then say "sha-crypt hash present" "yes ($donor)"; else say "sha-crypt hash present" "no"; fi

echo
if [ $fixed = 1 ]; then
  echo "not exposed: sshd has the fix."
elif [ $musl = 0 ]; then
  echo "not exposed: not musl."
elif [ $pam = 1 ]; then
  echo "not exposed: pam does the password check."
elif [ "$pwauth" = no ]; then
  echo "not exposed: password auth is off. (update anyway.)"
elif [ -z "$targets" ]; then
  echo "not exposed right now: no '*' accounts. the next 'adduser -D' changes that. update."
elif [ -z "$donor" ]; then
  echo "not exposed right now: no sha-crypt hash on the box. the next 'passwd' changes that. update."
else
  echo "EXPOSED. anyone can log in as: $targets"
  echo "fix: apk upgrade openssh (10.6p2), or set PasswordAuthentication no until you can."
  exposed=0
fi
[ $unsure = 1 ] && [ $exposed = 1 ] && { echo "(some checks couldn't run; treat this as 'probably'.)"; exit 2; }
exit $exposed
