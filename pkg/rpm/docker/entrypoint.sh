#!/bin/bash

set -xe

ref=$1

mkdir -p /tmp/repo
cd /tmp/repo
git clone https://github.com/gen0sec/synapse.git -b ${ref} --depth=1
cd synapse/pkg/rpm
./builder.sh
cp synapse-*.rpm /tmp/output/
chown 1000:1000 /tmp/output/synapse-*.rpm
