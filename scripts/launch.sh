#!/bin/bash

set -euo pipefail
BASEDIR=$(dirname $0)
source ${BASEDIR}/_utils.sh
source ${BASEDIR}/_config.sh

vm_arch=${config_vm_arch}
vm_name=${config_vm_name}
vm_distro=${config_vm_distro}

orbctl create -a ${vm_arch} ${vm_distro} ${vm_name}
