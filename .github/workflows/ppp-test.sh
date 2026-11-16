#!/usr/bin/env bash
set -euo pipefail
binary=$(realpath "$1")
test_name=tunnel::l2tp_v2::tests::ppp_session_transfers_packets_and_cleans_up
"$binary" --list --ignored | grep -Fx "$test_name: test"
tmp=$(mktemp -d)
cleanup() {
  jobs -pr | xargs -r kill 2>/dev/null || true
  ip netns del cat4igp-ppp-a 2>/dev/null || true
  ip netns del cat4igp-ppp-b 2>/dev/null || true
  rm -rf "$tmp"
}
trap cleanup EXIT
for mode in kernel userspace wireguard; do
  ip netns add cat4igp-ppp-a
  ip netns add cat4igp-ppp-b
  ip link add pppa type veth peer name pppb
  ip link set pppa netns cat4igp-ppp-a
  ip link set pppb netns cat4igp-ppp-b
  for side in a b; do
    ns=cat4igp-ppp-$side
    ip -n "$ns" link set lo up
    ip -n "$ns" link set ppp$side up
    if [[ $side == a ]]; then address=1; else address=2; fi
    if [[ $mode == wireguard ]]; then
      ip -n "$ns" address add "192.0.2.$address/24" dev ppp$side
      wg genkey > "$tmp/$side.key"
      wg pubkey < "$tmp/$side.key" > "$tmp/$side.pub"
      ip -n "$ns" link add wgtest type wireguard
    else
      ip -n "$ns" address add "198.18.0.$address/24" dev ppp$side
    fi
  done
  extra=()
  if [[ $mode == userspace ]]; then extra=(CAT4IGP_PPP_TEST_USERSPACE=1); fi
  if [[ $mode == wireguard ]]; then
    for side in a b; do
      if [[ $side == a ]]; then peer=b; address=2; port=51820; peerport=51821; else peer=a; address=1; port=51821; peerport=51820; fi
      ip netns exec "cat4igp-ppp-$side" wg set wgtest private-key "$tmp/$side.key" listen-port "$port" peer "$(cat "$tmp/$peer.pub")" allowed-ips 198.18.0.0/24 endpoint "192.0.2.$address:$peerport"
      ip -n "cat4igp-ppp-$side" link set wgtest mtu 9200 up
    done
    ip -n cat4igp-ppp-a link set pppa mtu 9500
    ip -n cat4igp-ppp-b link set pppb mtu 9500
    extra=(CAT4IGP_PPP_TEST_POLICY=1 CAT4IGP_PPP_TEST_JUMBO=1)
  fi
  echo "Running PPP $mode"
  ip netns exec cat4igp-ppp-b env "${extra[@]}" CAT4IGP_PPP_TEST_ROLE=listener "$binary" --exact "$test_name" --ignored --nocapture &
  listener=$!
  sleep 2
  status=0
  ip netns exec cat4igp-ppp-a env "${extra[@]}" CAT4IGP_PPP_TEST_ROLE=caller "$binary" --exact "$test_name" --ignored --nocapture || status=$?
  wait "$listener" || status=$?
  (( status == 0 ))
  ip netns del cat4igp-ppp-a
  ip netns del cat4igp-ppp-b
done
