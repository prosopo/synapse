#!/bin/bash

set -xe

ref=$1

cd /tmp/repo/pkg/deb
./builder.sh
cp synapse_*.deb /tmp/output/
chown 1000:1000 /tmp/output/synapse_*.deb
