#!/bin/bash

# Copyright (C) 2025, Gen0Sec.
# Dependencies: curl, devscripts, equivs, tar, gcc, gzip, pkg-config, libssl-dev
set -ex

brand="synapse"
target_dir=$(pwd)
if [ $(uname -i) = "x86_64" ]; then architecture="amd64"; elif [ $(uname -i) = "aarch64" ]; then architecture="arm64"; fi
base_dir="${target_dir}/../../"
version="$(grep -m1 'version' ${base_dir}/Cargo.toml | cut -d' ' -f3 | tr -d '"')"
release="1"

# Build directories
build_dir="/tmp/${brand}"
pkg_name="${brand}_${version}-${release}"
sources_dir="${build_dir}/${pkg_name}"
pkg_dir="${sources_dir}/pkg/deb"

mkdir -p ${sources_dir}
cp -R ${base_dir}/* ${sources_dir}/
sed -i "s|SYNAPSE_VERSION|${version}|g" ${sources_dir}/pkg/synapse.1

# Generating directory structure to build the .deb package
cd ${build_dir} && tar -czf ${pkg_name}.orig.tar.gz "${pkg_name}"

# Installing build dependencies
cd ${pkg_dir}
# Ensure devscripts and equivs are installed (required for mk-build-deps)
if ! command -v mk-build-deps &> /dev/null; then
    sudo apt-get update
    sudo apt-get install -y curl devscripts equivs tar gcc gzip pkg-config git build-essential clang llvm \
                    libelf-dev libssl-dev \
                    zlib1g-dev libzstd-dev pkg-config libcap-dev \
                    binutils-multiarch-dev cmake
fi
mk-build-deps -ir -t "apt-get -o Debug::pkgProblemResolver=yes -y"

# Build package
debuild -b -uc -us

full_pkg_name="${pkg_name}_${architecture}.deb"
mv "${pkg_dir}/../${full_pkg_name}" ${target_dir}/
rm -rf ${build_dir}
