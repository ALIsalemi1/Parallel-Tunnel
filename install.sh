#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $(uname -s) != Linux ]]; then
  echo "Linux is required." >&2
  exit 1
fi
case "$(uname -m)" in
  x86_64|amd64)
    arch=amd64
    checksum=2852af0cb20a13139b3448992e69b868e50ed0f8a1e5940ee1de9e19a123b613
    ;;
  aarch64|arm64)
    arch=arm64
    checksum=05de75d6994a2783699815ee553bd5a9327d8b79991de36e38b66862782f54ae
    ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
for command in curl tar sha256sum install; do
  command -v "$command" >/dev/null || { echo "Missing dependency: $command" >&2; exit 1; }
done
if [[ ! -w /usr/local/bin ]]; then
  echo "Run this installer as root or with sudo." >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
revision=41f9bd419fe593b6c381a8f49151b4efa270131f
base="https://raw.githubusercontent.com/ALIsalemi1/Parallel-Tunnel/$revision"
for file in go.mod go.sum main.go; do
  curl --retry 3 -fsSL "$base/$file" -o "$tmp/$file"
done
archive="go1.25.0.linux-$arch.tar.gz"
echo "Downloading Go toolchain for $arch..."
curl --retry 3 -fsSL "https://go.dev/dl/$archive" -o "$tmp/$archive"
echo "$checksum  $tmp/$archive" | sha256sum -c -
tar -xzf "$tmp/$archive" -C "$tmp"
echo "Building Parallel Tunnel..."
(
  cd "$tmp"
  CGO_ENABLED=0 GOTOOLCHAIN=local "$tmp/go/bin/go" build -trimpath -o parallel-tunnel .
)
install -m 0755 "$tmp/parallel-tunnel" /usr/local/bin/parallel-tunnel
echo "Installed /usr/local/bin/parallel-tunnel"
echo "Setup instructions: https://github.com/ALIsalemi1/Parallel-Tunnel#readme"

