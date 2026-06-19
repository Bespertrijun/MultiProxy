#!/bin/bash
set -euo pipefail

# multiProxy Panel 一键安装脚本
# 用法: curl -sL https://github.com/Bespertrijun/MultiProxy/releases/latest/download/install-panel.sh | bash
#
# 可选参数:
#   --admin-pass <PASS>   管理员密码 (必填,无默认值)
#   --dns-port <PORT>     GeoDNS 端口 (默认 53)
#   --http <ADDR:PORT>    Web 绑定 (默认 0.0.0.0:8080)
#   --data-dir <DIR>      数据目录 (默认 /opt/multiproxy)
#   --no-geocn            跳过下载 GeoCN IP 库
#   --no-systemd          不安装 systemd 服务

REPO="Bespertrijun/MultiProxy"
DATA_DIR="/opt/multiproxy"
ADMIN_PASS=""
DNS_PORT="53"
HTTP_BIND="0.0.0.0:8080"
SKIP_GEOCN=false
SKIP_SYSTEMD=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --admin-pass) ADMIN_PASS="$2"; shift 2;;
    --dns-port) DNS_PORT="$2"; shift 2;;
    --http) HTTP_BIND="$2"; shift 2;;
    --data-dir) DATA_DIR="$2"; shift 2;;
    --no-geocn) SKIP_GEOCN=true; shift;;
    --no-systemd) SKIP_SYSTEMD=true; shift;;
    *) echo "未知参数: $1"; exit 1;;
  esac
done

if [[ -z "$ADMIN_PASS" ]]; then
  echo "错误: 必须指定 --admin-pass"
  echo "用法: curl -sL .../install-panel.sh | bash -s -- --admin-pass \"你的密码\""
  exit 1
fi

# 检测架构
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) BINARY="panel-linux-x86_64";;
  *) echo "面板目前仅支持 x86_64 架构 (当前: $ARCH)"; exit 1;;
esac

echo "================================================"
echo "  multiProxy Panel 安装脚本"
echo "  架构: $ARCH"
echo "  数据目录: $DATA_DIR"
echo "  DNS 端口: $DNS_PORT"
echo "  Web 绑定: $HTTP_BIND"
echo "================================================"

# 创建目录
mkdir -p "$DATA_DIR/certs" "$DATA_DIR/dist"

# 下载面板二进制
echo ""
echo "[1/4] 下载 panel 二进制..."
DOWNLOAD_URL="https://github.com/$REPO/releases/latest/download/$BINARY"
curl -fSL "$DOWNLOAD_URL" -o /usr/local/bin/panel
chmod +x /usr/local/bin/panel
echo "  ✓ 已下载: /usr/local/bin/panel ($(du -h /usr/local/bin/panel | cut -f1))"

# 初始化数据库 + 管理员
echo ""
echo "[2/4] 初始化数据库和管理员用户..."
panel init \
  --db "sqlite://$DATA_DIR/panel.db" \
  --admin-pass "$ADMIN_PASS" \
  --key-file "$DATA_DIR/panel.key" \
  2>&1 || true
echo "  ✓ 数据库: $DATA_DIR/panel.db"
echo "  ✓ 加密密钥: $DATA_DIR/panel.key"

# 下载 GeoCN IP 库
if [[ "$SKIP_GEOCN" == "false" ]]; then
  echo ""
  echo "[3/4] 下载 GeoCN IP 库..."
  panel fetch-geocn --output "$DATA_DIR/GeoCN.mmdb" 2>&1 || echo "  ⚠ 下载失败,可稍后在面板中在线更新"
  if [[ -f "$DATA_DIR/GeoCN.mmdb" ]]; then
    echo "  ✓ IP 库: $DATA_DIR/GeoCN.mmdb ($(du -h "$DATA_DIR/GeoCN.mmdb" | cut -f1))"
  fi
else
  echo ""
  echo "[3/4] 跳过 GeoCN IP 库下载 (--no-geocn)"
fi

# 安装服务 (自动检测 systemd / OpenRC / 裸跑)
PANEL_CMD="/usr/local/bin/panel serve --db sqlite://$DATA_DIR/panel.db --http $HTTP_BIND --dns-port $DNS_PORT --geocn $DATA_DIR/GeoCN.mmdb --key-file $DATA_DIR/panel.key --cert-dir $DATA_DIR/certs --agent-bin-dir $DATA_DIR/dist"

if [[ "$SKIP_SYSTEMD" == "true" ]]; then
  echo ""
  echo "[4/4] 跳过服务安装 (--no-systemd)"
  echo ""
  echo "手动启动:"
  echo "  $PANEL_CMD"
elif command -v systemctl &>/dev/null && systemctl --version &>/dev/null 2>&1; then
  # systemd
  echo ""
  echo "[4/4] 安装 systemd 服务..."
  cat > /etc/systemd/system/multiproxy-panel.service <<EOF
[Unit]
Description=multiProxy Panel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$PANEL_CMD
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now multiproxy-panel
  echo "  ✓ 服务已启动: multiproxy-panel.service (systemd)"
elif command -v rc-service &>/dev/null; then
  # OpenRC (Alpine)
  echo ""
  echo "[4/4] 安装 OpenRC 服务..."
  cat > /etc/init.d/multiproxy-panel <<'INITEOF'
#!/sbin/openrc-run

name="multiproxy-panel"
description="multiProxy Panel"
command="/usr/local/bin/panel"
command_args="serve --db sqlite://DATADIR/panel.db --http HTTPBIND --dns-port DNSPORT --geocn DATADIR/GeoCN.mmdb --key-file DATADIR/panel.key --cert-dir DATADIR/certs --agent-bin-dir DATADIR/dist"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
output_log="/var/log/multiproxy-panel.log"
error_log="/var/log/multiproxy-panel.log"

depend() {
    need net
    after firewall
}
INITEOF
  # 替换占位符
  sed -i "s|DATADIR|$DATA_DIR|g; s|HTTPBIND|$HTTP_BIND|g; s|DNSPORT|$DNS_PORT|g" /etc/init.d/multiproxy-panel
  chmod +x /etc/init.d/multiproxy-panel
  rc-update add multiproxy-panel default
  rc-service multiproxy-panel start
  echo "  ✓ 服务已启动: multiproxy-panel (OpenRC)"
else
  # 无服务管理器,用 nohup 后台跑
  echo ""
  echo "[4/4] 未检测到 systemd 或 OpenRC,使用 nohup 后台启动..."
  nohup $PANEL_CMD > /var/log/multiproxy-panel.log 2>&1 &
  echo $! > /run/multiproxy-panel.pid
  echo "  ✓ 已后台启动 (PID: $!)"
  echo "  日志: /var/log/multiproxy-panel.log"
  echo "  停止: kill \$(cat /run/multiproxy-panel.pid)"
fi

echo ""
echo "================================================"
echo "  ✓ 安装完成!"
echo ""
echo "  面板地址: http://<你的IP>:${HTTP_BIND##*:}"
echo "  管理员: admin / <你设置的密码>"
echo "  DNS 端口: $DNS_PORT"
echo ""
echo "  数据文件:"
echo "    $DATA_DIR/panel.db      数据库"
echo "    $DATA_DIR/panel.key     加密密钥 (请备份!)"
echo "    $DATA_DIR/GeoCN.mmdb    IP 库"
echo ""
echo "  下一步:"
echo "    1. 打开面板 → 系统设置 → 配置 Cloudflare"
echo "    2. 添加 DNS 域名"
echo "    3. 添加节点 → 复制安装命令到 NAT 小鸡"
echo ""
echo "  日志: journalctl -u multiproxy-panel -f"
echo "================================================"
