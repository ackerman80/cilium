#!/bin/bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

TEST_NAME=$(get_filename_without_extension $0)
LOGS_DIR="${dir}/cilium-files/${TEST_NAME}/logs"
redirect_debug_logs ${LOGS_DIR}

set -ex # Required for the linter

log "${TEST_NAME} has been deprecated and replaced by test/runtime/Policies.go:Test CIDR Limit"
exit 0

function cleanup() {
  gather_files 20-cidr-limit ${TEST_SUITE}
  log "removing container id.server2"
  docker rm -f id.service2 2> /dev/null || true
  log "deleting all policies from cilium"
  cilium policy delete --all 2> /dev/null || true
  log "stopping cilium with systemctl"
  systemctl stop cilium
  wait_for_cilium_shutdown
  log "running \"cilium cleanup -f\""
  log "cleanup: `cilium cleanup -f`"
  log "starting cilium with systemctl"
  systemctl start cilium
  wait_for_cilium_status
}

trap cleanup EXIT

ID=""
function spin_up_container() {
  docker run -d --net $TEST_NET -l id.service2 --name id.service2 httpd
  wait_for_endpoints 1

  cilium config Debug=True
  ID=`cilium endpoint list|grep service|awk '{ print $1}'`
  log "endpoint is $ID"
  cilium endpoint config $ID Debug=true
}

function gen_policy() {
  policy_file=$1
  max_ent=$2
  function gen_ent() {
      for x in $(seq 1 $max_ent); do
        i=$(( ( RANDOM % 31 )  + 1 ))
        b=$(( ( RANDOM % 255 )  + 1 ))
        c=$(( ( RANDOM % 255 )  + 1 ))
        d=$(( ( RANDOM % 255 )  + 1 ))
        echo "          \"20.$b.$c.$d/$i\"," >> $policy_file
      done
  }

  echo "[" >> $policy_file
  echo "  {" >> $policy_file
  echo "    \"endpointSelector\": {" >> $policy_file
  echo "      \"matchLabels\": {" >> $policy_file
  echo "        \"any:id.service2\": \"\"" >> $policy_file
  echo "      }" >> $policy_file
  echo "    }," >> $policy_file
  echo "    \"egress\": [" >> $policy_file
  echo "      {" >> $policy_file
  echo "	\"toCIDR\": [ " >> $policy_file
  gen_ent
  echo "          \"1.0.0.0/32\"" >> $policy_file
  echo "        ]," >> $policy_file
  echo "	\"fromCIDR\": [ " >>  $policy_file
  gen_ent
  echo "          \"1.0.0.0/24\"" >> $policy_file
  echo "        ]" >> $policy_file
  echo "      }" >> $policy_file
  echo "    ]" >> $policy_file
  echo "  }" >> $policy_file
  echo "]" >> $policy_file
}

# Check logs for verifier output, should not be present on success.
function check_for_verifier_output() {
  if journalctl --no-pager --since "${SINCE}" -u cilium | grep "Verifier analysis"; then
    abort "`journalctl -u cilium --since \"${SINCE}\" | grep -B20 -F10 Verifier`"
  fi
}

create_cilium_docker_network
spin_up_container

log "will generate and import random policies"
SINCE="$(date +'%F %T')"
for x in $(seq 1 3); do
  check_for_verifier_output
  for i in $(seq 1 41); do
    check_for_verifier_output
    policy_file=`mktemp`
    gen_policy $policy_file $i
    # At some point max limit can be reached by import even though it might be
    # too late.
    if ! cilium policy import $policy_file > /dev/null; then
      break
    fi
  done
done
check_for_verifier_output

test_succeeded "${TEST_NAME}"
