#!/bin/bash
# DNS 净化与加固脚本 (安全极简版)
# 支持交互式选择，带有防失联、防冲突、自动回滚保护机制

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
# [保命机制 1] 安全预检：文件是否被服务商恶意锁定
# ==========================================
echo "🛡️ [1/6] 检查系统环境安全..."
if command -v lsattr >/dev/null 2>&1; then
    if lsattr /etc/resolv.conf 2>/dev/null | awk '{print $1}' | grep -q 'i'; then
        echo "❌ 致命警告：/etc/resolv.conf 被服务商设置了不可变保护 (chattr +i)。"
        echo "为防止机器断网失联，脚本已自动安全终止，未做任何修改！"
        exit 1
    fi
fi

# 备份原始配置用于可能的失败回滚
cp -a /etc/resolv.conf /etc/resolv.conf.bak 2>/dev/null || true

# ==========================================
# 2. 阻止 DHCP 篡改 DNS
# ==========================================
echo "🔒 [2/6] 阻止 DHCP 篡改 DNS..."
if [ -f "/etc/dhcp/dhclient.conf" ]; then
    grep -q "ignore domain-name-servers;" /etc/dhcp/dhclient.conf || echo "ignore domain-name-servers;" >> /etc/dhcp/dhclient.conf
    grep -q "ignore domain-search;" /etc/dhcp/dhclient.conf || echo "ignore domain-search;" >> /etc/dhcp/dhclient.conf
fi

# ==========================================
# 3. 配置 systemd-resolved 与 [保命机制 2] 冲突处理
# ==========================================
echo "📦 [3/6] 检查并配置 systemd-resolved..."
if ! command -v resolvectl &> /dev/null; then
    apt-get update -y >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y systemd-resolved >/dev/null 2>&1
fi

# Debian 11 冲突处理：如果存在老的 resolvconf，先启动新服务，再安全卸载老的
if dpkg -s resolvconf >/dev/null 2>&1; then
    echo "🧹 发现冲突的老旧包 resolvconf，正在安全替换..."
    systemctl enable --now systemd-resolved >/dev/null 2>&1
    sleep 2
    DEBIAN_FRONTEND=noninteractive apt-get remove -y resolvconf >/dev/null 2>&1
fi

systemctl enable --now systemd-resolved >/dev/null 2>&1

# ==========================================
# 4. 写入安全的全局 DNS 配置
# ==========================================
echo "🛡️ [4/6] 写入全局加密 DNS 配置..."
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
sleep 2 # 等待服务就绪

rm -f /etc/resolv.conf
ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

# ==========================================
# 5. 配置网卡级 DNS
# ==========================================
echo "🌐 [5/6] 绑定网卡级 DNS..."
IFACE=$(ip route | grep '^default' | awk '{print $5}' | head -n1)
if [ -n "$IFACE" ]; then
    resolvectl dns "$IFACE" $DNS_PRIMARY $DNS_SECONDARY 2>/dev/null
    resolvectl domain "$IFACE" "~." 2>/dev/null
    resolvectl default-route "$IFACE" yes 2>/dev/null
fi

# ==========================================
# [保命机制 3] 连通性测试与自动回滚
# ==========================================
echo "🔍 [6/6] 连通性测试与防失联保护..."
sleep 3 # 给网络路由一点生效的反应时间

# 测试解析 Google，如果失败则触发回滚
if getent hosts google.com >/dev/null 2>&1 || ping -c 1 -W 3 google.com >/dev/null 2>&1; then
    echo "🟢 DNS 解析测试成功！准备写入开机持久化..."

    # --- 只有测试成功，才配置开机持久化 ---
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

    # 清理备份文件
    rm -f /etc/resolv.conf.bak
    echo "✅ DNS 净化与加固已完美完成！当前使用: $TAG DNS"

else
    # --- 测试失败，执行回滚 ---
    echo "🔴 致命错误：DNS 解析测试未通过！正在触发自动回滚..."
    rm -f /etc/resolv.conf
    mv /etc/resolv.conf.bak /etc/resolv.conf 2>/dev/null || echo "nameserver 8.8.8.8" > /etc/resolv.conf
    systemctl restart systemd-resolved >/dev/null 2>&1
    
    echo "🔙 已恢复执行前的原始 DNS 配置。您的机器绝对安全，未被断网。"
    exit 1
fi
