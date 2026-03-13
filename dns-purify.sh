#!/bin/bash
# DNS 净化与加固脚本 (独立精简版)
# 支持交互式选择 Google DNS 或 Cloudflare DNS

if [[ ${EUID:-0} -ne 0 ]]; then
    echo "❌ 请以 root 身份运行此脚本。"
    exit 1
fi

# ==========================================
# 1. 交互式选择 DNS 组
# ==========================================
CHOICE=$1
if [ -z "$CHOICE" ]; then
    clear
    echo "====================================================="
    echo "请选择要使用的 DNS 提供商 (将配置为全局加密 DNS):"
    echo "1) Google DNS (8.8.8.8 / 8.8.4.4) - 默认"
    echo "2) Cloudflare DNS (1.1.1.1 / 1.0.0.1)"
    echo "====================================================="
    read -p "请输入数字 [1/2]: " INPUT
    case $INPUT in
        2) CHOICE="cf" ;;
        *) CHOICE="google" ;;
    esac
fi

if [ "$CHOICE" == "cf" ]; then
    DNS_PRIMARY="1.1.1.1"
    DNS_SECONDARY="1.0.0.1"
    # 配置 DoT (DNS over TLS) 需要对应的 SNI 域名
    RESOLVED_DNS="1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com"
    TAG="Cloudflare"
else
    DNS_PRIMARY="8.8.8.8"
    DNS_SECONDARY="8.8.4.4"
    RESOLVED_DNS="8.8.8.8#dns.google 8.8.4.4#dns.google"
    TAG="Google"
fi

echo "🚀 开始执行 DNS 净化与加固 (目标: $TAG DNS)..."

# ==========================================
# 2. 阻止 DHCP 篡改 DNS
# ==========================================
echo "🔒 [1/5] 阻止 DHCP 篡改 DNS..."
if [ -f "/etc/dhcp/dhclient.conf" ]; then
    grep -q "ignore domain-name-servers;" /etc/dhcp/dhclient.conf || echo "ignore domain-name-servers;" >> /etc/dhcp/dhclient.conf
    grep -q "ignore domain-search;" /etc/dhcp/dhclient.conf || echo "ignore domain-search;" >> /etc/dhcp/dhclient.conf
fi

# ==========================================
# 3. 配置 systemd-resolved
# ==========================================
echo "📦 [2/5] 检查并配置 systemd-resolved..."
if ! command -v resolvectl &> /dev/null; then
    apt-get update -y >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y systemd-resolved >/dev/null 2>&1
fi
systemctl enable --now systemd-resolved >/dev/null 2>&1

# ==========================================
# 4. 写入安全的全局 DNS 配置
# ==========================================
echo "🛡️ [3/5] 写入全局加密 DNS 配置..."
# 注意：这里会把上面选择的 $RESOLVED_DNS 变量动态写进去
cat > /etc/systemd/resolved.conf << EOF
[Resolve]
DNS=$RESOLVED_DNS
DNSOverTLS=yes
DNSSEC=no
LLMNR=no
MulticastDNS=no
Cache=yes
DNSStubListener=yes
EOF

systemctl restart systemd-resolved
rm -f /etc/resolv.conf
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

# ==========================================
# 5. 配置网卡级 DNS (立即生效)
# ==========================================
echo "🌐 [4/5] 绑定网卡级 DNS..."
IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -n1)
if [ -n "$IFACE" ]; then
    resolvectl dns "$IFACE" $DNS_PRIMARY $DNS_SECONDARY
    resolvectl domain "$IFACE" "~."
    resolvectl default-route "$IFACE" yes
fi

# ==========================================
# 6. 配置开机持久化
# ==========================================
echo "💾 [5/5] 配置开机持久化..."
# 注意：这里用 \$IFACE 转义，防止它在生成脚本时被提前解析，而保留 $DNS_PRIMARY 让它直接写入数值
cat > /usr/local/bin/dns-purify-apply.sh << EOF
#!/bin/bash
IFACE=\$(ip route | grep '^default' | awk '{print \$5}' | head -n1)
if [ -z "\$IFACE" ] || ! command -v resolvectl >/dev/null; then exit 0; fi
for i in \$(seq 1 15); do resolvectl status >/dev/null 2>&1 && break; sleep 2; done
resolvectl dns "\$IFACE" $DNS_PRIMARY $DNS_SECONDARY 2>/dev/null
resolvectl domain "\$IFACE" "~." 2>/dev/null
resolvectl default-route "\$IFACE" yes 2>/dev/null
EOF
chmod +x /usr/local/bin/dns-purify-apply.sh

# 创建持久化系统服务
cat > /etc/systemd/system/dns-purify-persist.service << 'EOF'
[Unit]
Description=DNS Purify Persist
After=systemd-resolved.service network-online.target
Wants=systemd-resolved.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/bin/dns-purify-apply.sh

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable dns-purify-persist.service >/dev/null 2>&1

echo "✅ DNS 净化与加固完成！当前使用: $TAG DNS"
ping -c 1 google.com >/dev/null 2>&1 && echo "🟢 解析测试成功" || echo "🔴 解析测试失败"
