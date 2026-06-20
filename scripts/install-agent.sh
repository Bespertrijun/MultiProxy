#!/bin/bash
set -euo pipefail

# multiProxy Agent 一键安装/卸载脚本
# 安装: curl -sL https://github.com/Bespertrijun/MultiProxy/releases/latest/download/install-agent.sh | bash -s -- \
#   --panel-url wss://panel.example.com/agent \
#   --node-id NODE_ID --token TOKEN
#
# 卸载: curl -sL .../install-agent.sh | bash -s -- --uninstall
#
# 可选参数:
#   --config-dir <DIR>    配置目录 (默认 /etc/multiproxy)
#   --no-gost             跳过下载 gost/realm
#   --no-systemd          不安装系统服务

REPO="Bespertrijun/MultiProxy"
PANEL_URL="" NODE_ID="" TOKEN=""
CONFIG_DIR="/etc/multiproxy"
SKIP_GOST=false
SKIP_SYSTEMD=false
UNINSTALL=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --panel-url) PANEL_URL="$2"; shift 2;;
    --node-id) NODE_ID="$2"; shift 2;;
    --token) TOKEN="$2"; shift 2;;
    --config-dir) CONFIG_DIR="$2"; shift 2;;
    --no-gost) SKIP_GOST=true; shift;;
    --no-systemd) SKIP_SYSTEMD=true; shift;;
    --uninstall) UNINSTALL=true; shift;;
    *) echo "未知参数: $1"; exit 1;;
  esac
done

# ========== 卸载 ==========
if [[ "$UNINSTALL" == "true" ]]; then
  echo "================================================"
  echo "  multiProxy Agent 卸载"
  echo "================================================"

  # 停止并移除服务
  if command -v systemctl &>/dev/null && systemctl is-active multiproxy-agent &>/dev/null 2>&1; then
    systemctl stop multiproxy-agent
    systemctl disable multiproxy-agent
    rm -f /etc/systemd/system/multiproxy-agent.service
    systemctl daemon-reload
    echo "  ✓ 已移除 systemd 服务"
  elif command -v rc-service &>/dev/null && [[ -f /etc/init.d/multiproxy-agent ]]; then
    rc-service multiproxy-agent stop 2>/dev/null || true
    rc-update del multiproxy-agent default 2>/dev/null || true
    rm -f /etc/init.d/multiproxy-agent
    echo "  ✓ 已移除 OpenRC 服务"
  elif [[ -f /run/multiproxy-agent.pid ]]; then
    kill "$(cat /run/multiproxy-agent.pid)" 2>/dev/null || true
    rm -f /run/multiproxy-agent.pid
    echo "  ✓ 已停止后台进程"
  fi

  # 删除二进制
  rm -f /usr/local/bin/agent
  echo "  ✓ 已删除 /usr/local/bin/agent"

  # 询问是否删除 gost/realm
  if [[ -f /usr/local/bin/gost ]]; then
    rm -f /usr/local/bin/gost
    echo "  ✓ 已删除 /usr/local/bin/gost"
  fi
  if [[ -f /usr/local/bin/realm ]]; then
    rm -f /usr/local/bin/realm
    echo "  ✓ 已删除 /usr/local/bin/realm"
  fi

  # 删除配置和日志
  if [[ -d "$CONFIG_DIR" ]]; then
    rm -rf "$CONFIG_DIR"
    echo "  ✓ 已删除配置目录 $CONFIG_DIR"
  fi
  rm -f /var/log/multiproxy-agent.log

  echo ""
  echo "  ✓ 卸载完成!"
  echo "================================================"
  exit 0
fi

# ========== 安装 ==========
if [[ -z "$PANEL_URL" || -z "$NODE_ID" || -z "$TOKEN" ]]; then
  echo "错误: 必须指定 --panel-url, --node-id, --token"
  echo "用法: curl -sL .../install-agent.sh | bash -s -- --panel-url URL --node-id ID --token TOKEN"
  echo "卸载: curl -sL .../install-agent.sh | bash -s -- --uninstall"
  exit 1
fi

# 检测架构
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) BINARY="agent-linux-x86_64"; GOST_ARCH="amd64"; REALM_ARCH="x86_64";;
  aarch64|arm64) BINARY="agent-linux-aarch64"; GOST_ARCH="arm64"; REALM_ARCH="aarch64";;
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

# 下载 gost + realm
if [[ "$SKIP_GOST" == "false" ]]; then
  echo ""
  echo "[2/3] 下载转发工具..."

  # gost
  GOST_TAG=$(curl -sI -o /dev/null -w "%{redirect_url}" --max-redirs 0 "https://github.com/go-gost/gost/releases/latest" 2>/dev/null | grep -oE '[^/]+$')
  if [[ -n "$GOST_TAG" ]]; then
    GOST_VER="${GOST_TAG#v}"
    GOST_URL="https://github.com/go-gost/gost/releases/download/${GOST_TAG}/gost_${GOST_VER}_linux_${GOST_ARCH}.tar.gz"
    if curl -fSL "$GOST_URL" -o /tmp/gost.tar.gz 2>/dev/null; then
      tar -xzf /tmp/gost.tar.gz -C /usr/local/bin/ gost
      chmod +x /usr/local/bin/gost
      rm -f /tmp/gost.tar.gz
      echo "  ✓ gost ${GOST_TAG}"
    else
      echo "  ⚠ gost 下载失败"
    fi
  else
    echo "  ⚠ 无法获取 gost 最新版本"
  fi

  # realm
  REALM_TAG=$(curl -sI -o /dev/null -w "%{redirect_url}" --max-redirs 0 "https://github.com/zhboner/realm/releases/latest" 2>/dev/null | grep -oE '[^/]+$')
  if [[ -n "$REALM_TAG" ]]; then
    REALM_URL="https://github.com/zhboner/realm/releases/download/${REALM_TAG}/realm-${REALM_ARCH}-unknown-linux-musl.tar.gz"
    if curl -fSL "$REALM_URL" -o /tmp/realm.tar.gz 2>/dev/null; then
      tar -xzf /tmp/realm.tar.gz -C /usr/local/bin/
      chmod +x /usr/local/bin/realm
      rm -f /tmp/realm.tar.gz
      echo "  ✓ realm ${REALM_TAG}"
    else
      echo "  ⚠ realm 下载失败"
    fi
  else
    echo "  ⚠ 无法获取 realm 最新版本"
  fi
else
  echo ""
  echo "[2/3] 跳过转发工具下载 (--no-gost)"
fi

# 创建配置目录
mkdir -p "$CONFIG_DIR"

# 安装服务 (自动检测 systemd / OpenRC / 裸跑)
AGENT_CMD="/usr/local/bin/agent --panel-url \"$PANEL_URL\" --node-id \"$NODE_ID\" --token \"$TOKEN\" --config-dir \"$CONFIG_DIR\""

if [[ "$SKIP_SYSTEMD" == "true" ]]; then
  echo ""
  echo "[3/3] 跳过服务安装 (--no-systemd)"
  echo ""
  echo "手动启动:"
  echo "  $AGENT_CMD"
elif command -v systemctl &>/dev/null && systemctl --version &>/dev/null 2>&1; then
  # systemd
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
  echo "  ✓ 服务已启动: multiproxy-agent.service (systemd)"
elif command -v rc-service &>/dev/null; then
  # OpenRC (Alpine)
  echo ""
  echo "[3/3] 安装 OpenRC 服务..."
  cat > /etc/init.d/multiproxy-agent <<INITEOF
#!/sbin/openrc-run

name="multiproxy-agent"
description="multiProxy Agent"
command="/usr/local/bin/agent"
command_args="--panel-url $PANEL_URL --node-id $NODE_ID --token $TOKEN --config-dir $CONFIG_DIR"
command_background=true
pidfile="/run/\${RC_SVCNAME}.pid"
output_log="/var/log/multiproxy-agent.log"
error_log="/var/log/multiproxy-agent.log"

depend() {
    need net
    after firewall
}
INITEOF
  chmod +x /etc/init.d/multiproxy-agent
  rc-update add multiproxy-agent default
  rc-service multiproxy-agent start
  echo "  ✓ 服务已启动: multiproxy-agent (OpenRC)"
else
  # 无服务管理器,用 nohup 后台跑
  echo ""
  echo "[3/3] 未检测到 systemd 或 OpenRC,使用 nohup 后台启动..."
  nohup /usr/local/bin/agent \
    --panel-url "$PANEL_URL" \
    --node-id "$NODE_ID" \
    --token "$TOKEN" \
    --config-dir "$CONFIG_DIR" \
    > /var/log/multiproxy-agent.log 2>&1 &
  echo $! > /run/multiproxy-agent.pid
  echo "  ✓ 已后台启动 (PID: $!)"
  echo "  日志: /var/log/multiproxy-agent.log"
  echo "  停止: kill \$(cat /run/multiproxy-agent.pid)"
fi

echo ""
echo "================================================"
echo "  ✓ 安装完成!"
echo ""
echo "  二进制:  /usr/local/bin/agent"
echo "  Gost:    /usr/local/bin/gost"
echo "  Realm:   /usr/local/bin/realm"
echo "  配置:    $CONFIG_DIR"
echo ""
echo "  卸载:    curl -sL .../install-agent.sh | bash -s -- --uninstall"
echo "================================================"
