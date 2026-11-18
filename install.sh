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
revision=6d919c08920306d2ce0a065cea839c858fda6303
base="https://raw.githubusercontent.com/ALIsalemi1/Parallel-Tunnel/$revision"
for file in go.mod go.sum main.go; do
  curl --retry 3 -fsSL "$base/$file" -o "$tmp/$file"
done
archive="go1.25.0.linux-$arch.tar.gz"
echo "Downloading Go toolchain for $arch..."
download_go() {
  curl --retry 2 --connect-timeout 15 -fsSL "$1/$archive" -o "$tmp/$archive" &&
    printf '%s  %s\n' "$checksum" "$tmp/$archive" | sha256sum -c -
}
if ! download_go https://go.dev/dl; then
  echo "Trying the Go mirror..." >&2
  download_go https://mirrors.aliyun.com/golang
fi
tar -xzf "$tmp/$archive" -C "$tmp"
echo "Building Parallel Tunnel..."
(
  cd "$tmp"
  CGO_ENABLED=0 GOTOOLCHAIN=local "$tmp/go/bin/go" build -trimpath -o parallel-tunnel .
)
install -m 0755 "$tmp/parallel-tunnel" /usr/local/bin/parallel-tunnel
echo "Installed /usr/local/bin/parallel-tunnel"
echo "Setup instructions: https://github.com/ALIsalemi1/Parallel-Tunnel#readme"
