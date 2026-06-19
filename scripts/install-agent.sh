#!/bin/bash
set -euo pipefail

# multiProxy Agent 一键安装脚本
# 用法: curl -sL https://github.com/Bespertrijun/MultiProxy/releases/latest/download/install-agent.sh | bash -s -- \
#   --panel-url wss://panel.example.com/agent \
#   --node-id NODE_ID --token TOKEN
#
# 可选参数:
#   --config-dir <DIR>    配置目录 (默认 /etc/multiproxy)
#   --no-gost             跳过下载 gost
#   --no-systemd          不安装 systemd 服务

REPO="Bespertrijun/MultiProxy"
PANEL_URL="" NODE_ID="" TOKEN=""
CONFIG_DIR="/etc/multiproxy"
SKIP_GOST=false
SKIP_SYSTEMD=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --panel-url) PANEL_URL="$2"; shift 2;;
    --node-id) NODE_ID="$2"; shift 2;;
    --token) TOKEN="$2"; shift 2;;
    --config-dir) CONFIG_DIR="$2"; shift 2;;
    --no-gost) SKIP_GOST=true; shift;;
    --no-systemd) SKIP_SYSTEMD=true; shift;;
    *) echo "未知参数: $1"; exit 1;;
  esac
done

if [[ -z "$PANEL_URL" || -z "$NODE_ID" || -z "$TOKEN" ]]; then
  echo "错误: 必须指定 --panel-url, --node-id, --token"
  echo "用法: curl -sL .../install-agent.sh | bash -s -- --panel-url URL --node-id ID --token TOKEN"
  exit 1
fi

# 检测架构
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) BINARY="agent-linux-x86_64"; GOST_ARCH="amd64";;
  aarch64|arm64) BINARY="agent-linux-aarch64"; GOST_ARCH="arm64";;
  *) echo "不支持的架构: $ARCH"; exit 1;;
esac

echo "================================================"
echo "  multiProxy Agent 安装脚本"
echo "  架构: $ARCH"
echo "  面板: $PANEL_URL"
echo "  节点: $NODE_ID"
echo "================================================"

# 下载 agent 二进制 (从 GitHub Releases)
echo ""
echo "[1/3] 下载 agent 二进制 ($BINARY)..."
DOWNLOAD_URL="https://github.com/$REPO/releases/latest/download/$BINARY"
curl -fSL "$DOWNLOAD_URL" -o /usr/local/bin/agent
chmod +x /usr/local/bin/agent
echo "  ✓ 已下载: /usr/local/bin/agent ($(du -h /usr/local/bin/agent | cut -f1))"

# 下载 gost
if [[ "$SKIP_GOST" == "false" ]]; then
  echo ""
  echo "[2/3] 下载 gost..."
  GOST_URL="https://github.com/go-gost/gost/releases/latest/download/gost_linux_${GOST_ARCH}"
  if curl -fSL "$GOST_URL" -o /usr/local/bin/gost 2>/dev/null; then
    chmod +x /usr/local/bin/gost
    echo "  ✓ 已下载: /usr/local/bin/gost"
  else
    echo "  ⚠ gost 下载失败,请手动安装 gost 或 realm"
  fi
else
  echo ""
  echo "[2/3] 跳过 gost 下载 (--no-gost)"
fi

# 创建配置目录
mkdir -p "$CONFIG_DIR"

# 安装 systemd 服务
if [[ "$SKIP_SYSTEMD" == "false" ]]; then
  echo ""
  echo "[3/3] 安装 systemd 服务..."
  cat > /etc/systemd/system/multiproxy-agent.service <<EOF
[Unit]
Description=multiProxy Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/agent \\
  --panel-url "$PANEL_URL" \\
  --node-id "$NODE_ID" \\
  --token "$TOKEN" \\
  --config-dir "$CONFIG_DIR"
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now multiproxy-agent
  echo "  ✓ 服务已启动: multiproxy-agent.service"
else
  echo ""
  echo "[3/3] 跳过 systemd 安装 (--no-systemd)"
  echo ""
  echo "手动启动:"
  echo "  agent --panel-url \"$PANEL_URL\" --node-id \"$NODE_ID\" --token \"$TOKEN\" --config-dir \"$CONFIG_DIR\""
fi

echo ""
echo "================================================"
echo "  ✓ 安装完成!"
echo ""
echo "  二进制:  /usr/local/bin/agent"
echo "  Gost:    /usr/local/bin/gost"
echo "  配置:    $CONFIG_DIR"
echo "  服务:    multiproxy-agent.service"
echo ""
echo "  自更新:  agent --self-update --panel-url \"$PANEL_URL\""
echo "  日志:    journalctl -u multiproxy-agent -f"
echo "================================================"
