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
for command in curl tar sha256sum install openssl systemctl; do
  command -v "$command" >/dev/null || { echo "Missing dependency: $command" >&2; exit 1; }
done
if [[ ! -w /usr/local/bin ]]; then
  echo "Run this installer as root or with sudo." >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
revision=7791d8fc774e48b985c85c7c1c3a740b99b52f88
base="https://raw.githubusercontent.com/ALIsalemi1/Parallel-Tunnel/$revision"
for file in go.mod go.sum main.go panel.go panel.html; do
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
# Install separately so the existing tunnel binary and services are preserved.
install -m 0755 "$tmp/parallel-tunnel" /usr/local/bin/parallel-tunnel-panel
install -d -m 0700 /etc/parallel-tunnel-panel
if [[ ! -e /etc/parallel-tunnel-panel/panel.password ]]; then
  (umask 077; openssl rand -hex 24 > /etc/parallel-tunnel-panel/panel.password)
fi
chmod 0600 /etc/parallel-tunnel-panel/panel.password
cat > /etc/systemd/system/parallel-tunnel-panel.service <<'UNIT'
[Unit]
Description=Parallel Tunnel Web Panel (preview)
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/parallel-tunnel-panel panel -listen 127.0.0.1:9090 -config /etc/parallel-tunnel-panel/panel.json -password-file /etc/parallel-tunnel-panel/panel.password
Restart=on-failure
RestartSec=5
UMask=0077
LimitNOFILE=262144
NoNewPrivileges=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable parallel-tunnel-panel.service
systemctl restart parallel-tunnel-panel.service
systemctl is-active --quiet parallel-tunnel-panel.service
echo "Panel installed separately: /usr/local/bin/parallel-tunnel-panel"
echo "Password file: /etc/parallel-tunnel-panel/panel.password"
echo "Forward SSH port 9090 to 127.0.0.1:9090, then open http://127.0.0.1:9090"
echo "Existing standalone tunnels are not imported automatically."
