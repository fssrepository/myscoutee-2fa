#!/usr/bin/env bash
set -euo pipefail

# Match the Go version used by this repository's Dockerfile.
version=1.26.2
checksum=990e6b4bbba816dc3ee129eaeaf4b42f17c2800b88a2166c265ac1a200262282

if [[ $(uname -s) != Linux || $(uname -m) != x86_64 ]]; then
  echo 'This installer requires Linux x86-64.' >&2
  exit 1
fi
if [[ -x /usr/local/bin/go && $(/usr/local/bin/go version) == "go version go${version} linux/amd64" ]]; then
  echo "Go ${version} is already installed system-wide."
  exit 0
fi
if [[ -e /usr/local/go || -e /usr/local/bin/go || -e /usr/local/bin/gofmt ]]; then
  echo 'A system Go installation already exists; inspect it before replacing anything.' >&2
  exit 1
fi

archive=$(mktemp /tmp/myscoutee-go.XXXXXXXX.tar.gz)
trap 'unlink "$archive"' EXIT
curl --fail --location --retry 3 --silent --show-error \
  --output "$archive" "https://go.dev/dl/go${version}.linux-amd64.tar.gz"
printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check

echo 'The official archive is verified. Enter your sudo password to install Go.'
sudo -v
sudo tar -C /usr/local -xzf "$archive"
sudo ln -s /usr/local/go/bin/go /usr/local/bin/go
sudo ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt
/usr/local/bin/go version
