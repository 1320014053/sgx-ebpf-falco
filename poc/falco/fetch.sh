#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "${1:?usage: fetch.sh DEPS_DIR}"
cd "$1"

archive() {
    local name=$1 url=$2 hash=${3:-}
    if [[ ! -d $name ]]; then
        curl --fail --location --silent --show-error --retry 2 "$url" -o "$name.tar.gz"
        if [[ -n $hash ]]; then
            echo "$hash  $name.tar.gz" | sha256sum --check
        fi
        mkdir "$name"
        tar -xzf "$name.tar.gz" --strip-components=1 -C "$name"
    fi
}

github=https://codeload.github.com
archive falco "$github/falcosecurity/falco/tar.gz/7625e203c17c88c91fa1b1b8e2937907f22a1523"
archive libs "$github/falcosecurity/libs/tar.gz/cea7e1d4fa6f64d3855a8e37d784088ae4846891"
archive yaml "$github/jbeder/yaml-cpp/tar.gz/c2bec4c755c67ad86185a2a264996137904fb712" faea1ffdbad81b958b3b45a63ba667f4db53a3fffb983ca5df4745cf90044797
archive njson "$github/nlohmann/json/tar.gz/refs/tags/v3.11.3" 0d8ef5af7f9794e3263480193c491549b2ba6cc74bb018906202ada498a79406
archive valijson "$github/tristanpenman/valijson/tar.gz/refs/tags/v1.0.2" 35d86e54fc727f1265226434dc996e33000a570f833537a25c8b702b0b824431
archive uthash "$github/troydhanson/uthash/tar.gz/refs/tags/v1.9.8" d9d123ce81c5d127442876fc3b12fab3ad632bee6aca685be7d461c08e24c046
archive re2 "$github/google/re2/tar.gz/refs/tags/2022-06-01" f89c61410a072e5cbcf8c27e3a778da7d6fd2f2b5b1445cd4f4508bee946ab0f
archive jsoncpp "$github/open-source-parsers/jsoncpp/tar.gz/refs/tags/1.9.5" f409856e5920c18d0c2fb85276e24ee607d2a09b5e7d5f0a371368903c275da2
archive zlib https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
archive plugins "$github/falcosecurity/plugins/tar.gz/9064e9d620538aebf32912fa00f6b9ef95d46a37"
archive plugin-sdk "$github/falcosecurity/plugin-sdk-cpp/tar.gz/refs/tags/0.3.0"
archive fmt "$github/fmtlib/fmt/tar.gz/refs/tags/11.1.4"
archive reflex "$github/Genivia/RE-flex/tar.gz/refs/tags/v5.3.0"
archive package https://download.falco.org/packages/bin/x86_64/falco-0.45.2-x86_64.tar.gz b2e9961e51601095765c6c644329673e6af2f06c02357d0e77da0f680e4910da
echo '30a1a60263ab97650c851011468da03b17fc0096a7cfa3b6686eba5de73b865b  package/etc/falco/falco_rules.yaml' | sha256sum --check

if [[ ! -d ert ]]; then
    curl -fLsS --retry 2 https://github.com/edgelesssys/edgelessrt/releases/download/v0.5.5/edgelessrt_0.5.5_amd64_ubuntu-22.04.deb -o edgelessrt.deb
    echo '49de92377917e0ddcbfd422466a769c38487188692e4ec6feab47dcf935c56b2  edgelessrt.deb' | sha256sum --check
    dpkg-deb -x edgelessrt.deb ert
fi

port_patches=(libs-sgx.patch libs-sgx-dns.patch libs-raw-block-async.patch)
if patch --dry-run --silent --reverse --force -p1 -d libs < "$here/libs-sgx-dns.patch" >/dev/null 2>&1; then
    port_patches=(libs-raw-block-async.patch)
fi
for port_patch in "${port_patches[@]}"; do
    if ! patch --dry-run --silent --reverse --force -p1 -d libs < "$here/$port_patch" >/dev/null 2>&1; then
        patch --silent -p1 -d libs < "$here/$port_patch"
    fi
done
