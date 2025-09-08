#!/bin/bash

set -euo pipefail
BASEDIR=$(dirname $0)
source ${BASEDIR}/../_utils.sh

docker_exists=$(which docker || true)
if [ -n "$docker_exists" ]; then
  log_dimmed "docker가 이미 설치되어 있습니다."
  log_dimmed "docker version: $(docker --version)"

else
  log_dimmed "docker를 설치합니다."
  if [ ! -e /etc/systemd/system/docker.socket.d/override.conf ]; then
    sudo mkdir -p /etc/systemd/system/docker.socket.d

    cat <<-EOF > /tmp/docker-socket-override.conf
[Socket]
SocketUser=$USER
EOF

    sudo mv /tmp/docker-socket-override.conf /etc/systemd/system/docker.socket.d/override.conf
  fi

  export DEBIAN_FRONTEND=noninteractive
  curl -fsSL https://get.docker.com | sh
fi

# install docker-ctop
ctop_exists=$(which ctop || true)
if [ -n "$ctop_exists" ]; then
  log_dimmed "docker-ctop이 이미 설치되어 있습니다."
  log_dimmed "docker-ctop version: $(ctop -v)"

else
  log_dimmed "docker-ctop을 설치합니다."
  sudo apt-get install ca-certificates curl gnupg lsb-release
  curl -fsSL https://azlux.fr/repo.gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/azlux-archive-keyring.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/azlux-archive-keyring.gpg] http://packages.azlux.fr/debian \
    stable main" | sudo tee /etc/apt/sources.list.d/azlux.list >/dev/null
  sudo apt-get update
  sudo apt-get install docker-ctop
fi