#!/bin/bash

BIGREEN='\033[1;92m'
DIMMED='\033[2m'
NC='\033[0m'

PREFIX="[SYSTEM] "
function log {
  echo -e "${BIGREEN}${PREFIX}${1}${NC}"
}

function log_dimmed {
  echo -e "${DIMMED}${PREFIX}${1}${NC}"
}

NO_COLOR=${NO_COLOR:-false}
if [ "$NO_COLOR" = true ]; then
  log() {
    echo -e "${PREFIX}${1}"
  }

  log_dimmed() {
    echo -e "${PREFIX}${1}"
  }
fi