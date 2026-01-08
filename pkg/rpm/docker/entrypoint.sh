#!/bin/bash

set -xe

ref=$1

cd /tmp/repo/pkg/rpm
./builder.sh
cp synapse-*.rpm /tmp/output/
chown 1000:1000 /tmp/output/synapse-*.rpm
