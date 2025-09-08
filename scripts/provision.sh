#!/bin/bash

set -euo pipefail
BASEDIR=$(dirname $0)
source ${BASEDIR}/_utils.sh
source ${BASEDIR}/_config.sh

vm_name=${config_vm_name}

log "[1/2] apt로 의존성 패키지들을 설치합니다."
orbctl run -m ${vm_name} ${BASEDIR}/dependencies/apt.sh

log "[2/2] docker 설치"
orbctl run -m ${vm_name} ${BASEDIR}/dependencies/docker.sh

log "VM 개발환경 설정이 완료되었습니다."
