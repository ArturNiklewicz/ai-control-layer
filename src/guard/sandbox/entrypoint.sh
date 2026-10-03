#!/bin/sh
# Runs as root only long enough to lock the network, then drops to the agent uid with no caps.
# Any failure here exits non-zero: the agent never starts without the firewall (fail closed).
set -eu
: "${AGENT_UID:?}" "${AGENT_GID:?}" "${ALLOW:?}"   # ALLOW="ip:port ip:port ..."

for t in iptables ip6tables; do
  $t -P INPUT DROP; $t -P FORWARD DROP; $t -P OUTPUT DROP
  $t -A INPUT -i lo -j ACCEPT;  $t -A OUTPUT -o lo -j ACCEPT
  $t -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  $t -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
done
for spec in $ALLOW; do   # IPv4 tcp allowlist; IPv6 stays fully closed
  iptables -A OUTPUT -p tcp -d "${spec%:*}" --dport "${spec##*:}" -j ACCEPT
done
# everything else (incl. DNS: names come from --add-host) is refused fast, not hung
iptables -A OUTPUT -p tcp -j REJECT --reject-with tcp-reset
iptables -A OUTPUT -j REJECT
ip6tables -A OUTPUT -j REJECT

chown "$AGENT_UID:$AGENT_GID" /home/agent /home/agent/.claude
exec setpriv --reuid "$AGENT_UID" --regid "$AGENT_GID" --clear-groups \
  --inh-caps=-all --bounding-set=-all --no-new-privs -- "$@"
