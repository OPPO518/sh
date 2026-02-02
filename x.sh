#!/bin/bash

# ===== 自我安装与别名清理 =====
current_script=$(readlink -f "$0")
target_path="/usr/local/bin/x"
if [ "$current_script" != "$target_path" ]; then
    cp -f "$current_script" "$target_path"
    chmod +x "$target_path"
fi

# ===== 全局颜色变量 =====
gl_hui='\e[37m'
gl_hong='\033[31m'
gl_lv='\033[32m'
gl_huang='\033[33m'
gl_lan='\033[34m'
gl_bai='\033[0m'
gl_kjlan='\033[96m'

# ===== 辅助函数：IP信息获取 =====
ip_address() {
    get_public_ip() { curl -s https://ipinfo.io/ip && echo; }
    get_local_ip() { ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[^ ]+' || hostname -I 2>/dev/null | awk '{print $1}'; }
    public_ip=$(get_public_ip)
    isp_info=$(curl -s --max-time 3 http://ipinfo.io/org)
    if echo "$isp_info" | grep -Eiq 'mobile|unicom|telecom'; then ipv4_address=$(get_local_ip); else ipv4_address="$public_ip"; fi
    ipv6_address=$(curl -s --max-time 1 https://v6.ipinfo.io/ip && echo)
}

# ===== 辅助函数：网络流量统计 =====
output_status() {
    output=$(awk 'BEGIN { rx_total = 0; tx_total = 0 }
        $1 ~ /^(eth|ens|enp|eno)[0-9]+/ { rx_total += $2; tx_total += $10 }
        END {
            rx_units = "Bytes"; tx_units = "Bytes";
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "K"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "M"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "G"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "K"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "M"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "G"; }
            printf("%.2f%s %.2f%s\n", rx_total, rx_units, tx_total, tx_units);
        }' /proc/net/dev)
    rx=$(echo "$output" | awk '{print $1}')
    tx=$(echo "$output" | awk '{print $2}')
}

# ===== 辅助函数：时区检测 =====
current_timezone() {
    if grep -q 'Alpine' /etc/issue; then date +"%Z %z"; else timedatectl | grep "Time zone" | awk '{print $3}'; fi
}

# ===== 功能模块: 系统初始化 (完整版) =====
system_initialize() {
    clear
    echo -e "${gl_kjlan}################################################"
    echo -e "#            系统初始化配置 (System Init)        #"
    echo -e "################################################${gl_bai}"
    
    local os_ver=""
    if grep -q "bullseye" /etc/os-release; then os_ver="11"; echo -e "当前系统: ${gl_huang}Debian 11 (Bullseye)${gl_bai}";
    elif grep -q "bookworm" /etc/os-release; then os_ver="12"; echo -e "当前系统: ${gl_huang}Debian 12 (Bookworm)${gl_bai}";
    else echo -e "${gl_hong}错误: 仅支持 Debian 11/12${gl_bai}"; read -p "按回车返回..."; return; fi
    
    echo -e "${gl_hui}* 包含换源、BBR、时区及防火墙内核参数${gl_bai}"
    echo -e "------------------------------------------------"
    echo -e "请设定当前 VPS 的业务角色："
    echo -e "${gl_lv} 1.${gl_bai} 落地机 (Landing)  -> [关闭转发 | 极简安全]"
    echo -e "${gl_lv} 2.${gl_bai} 中转机 (Transit)  -> [开启转发 | 路由优化]"
    echo -e "${gl_hui} 0. 返回主菜单${gl_bai}"
    echo -e "------------------------------------------------"
    read -p "请输入选项 [0-2]: " role_choice
    if [ "$role_choice" == "0" ]; then return; fi

    echo -e "${gl_kjlan}>>> 正在执行初始化...${gl_bai}"
    
    # 换源与基础软件
    [ -f /etc/apt/sources.list ] && mv /etc/apt/sources.list /etc/apt/sources.list.bak_$(date +%F)
    if [ "$os_ver" == "11" ]; then
        echo -e "deb http://deb.debian.org/debian bullseye main contrib non-free
deb http://deb.debian.org/debian bullseye-updates main contrib non-free
deb http://security.debian.org/debian-security bullseye-security main contrib non-free" > /etc/apt/sources.list
    else
        echo -e "deb http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian-security/ bookworm-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian/ bookworm-updates main contrib non-free non-free-firmware" > /etc/apt/sources.list
    fi

    export DEBIAN_FRONTEND=noninteractive
    apt update && apt upgrade -y -o Dpkg::Options::="--force-confold"
    apt install curl wget systemd-timesyncd socat cron rsync -y

    # 内核参数配置
    rm -f /etc/sysctl.d/99-vps-optimize.conf
    if [ "$role_choice" == "1" ]; then # 落地机
        cat > /etc/sysctl.d/99-vps-optimize.conf << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.netfilter.nf_conntrack_max = 1000000
net.nf_conntrack_max = 1000000
net.ipv4.icmp_echo_ignore_all = 0
EOF
    else # 中转机
        modprobe nft_nat 2>/dev/null; modprobe br_netfilter 2>/dev/null
        cat > /etc/sysctl.d/99-vps-optimize.conf << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 0
net.netfilter.nf_conntrack_max = 1000000
net.nf_conntrack_max = 1000000
net.ipv4.icmp_echo_ignore_all = 0
EOF
    fi
    sysctl --system
    
    timedatectl set-timezone Asia/Shanghai
    systemctl enable --now systemd-timesyncd
    
    echo -e "${gl_lv}初始化完成！${gl_bai}"
    if [ -f /var/run/reboot-required ]; then
        read -p "系统内核已更新，是否重启? (y/n): " rb
        [[ "$rb" =~ ^[yY]$ ]] && reboot
    else
        read -p "按回车返回..."
    fi
}

# ===== 功能模块: Swap 管理 (完整版) =====
swap_management() {
    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#            Swap 虚拟内存管理                     #"
        echo -e "################################################${gl_bai}"
        local swap_total=$(free -m | grep Swap | awk '{print $2}')
        echo -e "当前 Swap: ${gl_huang}${swap_total}MB${gl_bai}"
        echo -e "------------------------------------------------"
        echo -e "${gl_lv} 1.${gl_bai} 设置/扩容 Swap"
        echo -e "${gl_hong} 2.${gl_bai} 关闭/删除 Swap"
        echo -e "${gl_hui} 0. 返回${gl_bai}"
        echo -e "------------------------------------------------"
        read -p "选项: " c
        case "$c" in
            1)
                read -p "输入大小(MB): " s
                if [[ "$s" =~ ^[0-9]+$ ]]; then
                    echo "正在处理..."
                    swapoff -a 2>/dev/null; rm -f /swapfile; sed -i '/swapfile/d' /etc/fstab
                    dd if=/dev/zero of=/swapfile bs=1M count=$s status=progress
                    chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile
                    echo '/swapfile none swap sw 0 0' >> /etc/fstab
                    echo -e "${gl_lv}成功${gl_bai}"; read -p "..." 
                fi ;;
            2) swapoff -a; rm -f /swapfile; sed -i '/swapfile/d' /etc/fstab; echo -e "${gl_lv}已删除${gl_bai}"; read -p "..." ;;
            0) return ;;
        esac
    done
}

# ===== 功能模块: Nftables 防火墙 (完整版) =====
nftables_management() {
    detect_ssh_port() {
        local p=$(ss -tlnp | grep 'sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -n 1)
        echo "${p:-22}"
    }

    init_firewall() {
        local type=$1
        local port=$(detect_ssh_port)
        apt update && apt install nftables -y; systemctl enable nftables
        
        echo "#!/usr/sbin/nft -f" > /etc/nftables.conf
        echo "flush ruleset" >> /etc/nftables.conf
        
        if [ "$type" == "landing" ]; then
            cat >> /etc/nftables.conf << EOF
table inet my_landing {
    set allowed_tcp { type inet_service; flags interval; }
    set allowed_udp { type inet_service; flags interval; }
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept; ct state established,related accept; icmp type echo-request accept; icmpv6 type echo-request accept;
        tcp dport $port accept; tcp dport @allowed_tcp accept; udp dport @allowed_udp accept;
    }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain output { type filter hook output priority 0; policy accept; }
}
EOF
        else
            cat >> /etc/nftables.conf << EOF
table inet my_transit {
    set local_tcp { type inet_service; flags interval; }
    set local_udp { type inet_service; flags interval; }
    map fwd_tcp { type inet_service : ipv4_addr . inet_service; }
    map fwd_udp { type inet_service : ipv4_addr . inet_service; }
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept; ct state established,related accept; icmp type echo-request accept; icmpv6 type echo-request accept;
        tcp dport $port accept; tcp dport @local_tcp accept; udp dport @local_udp accept;
    }
    chain forward { type filter hook forward priority 0; policy accept; ct state established,related accept; tcp flags syn tcp option maxseg size set 1360; }
    chain prerouting { type nat hook prerouting priority -100; policy accept; dnat ip to tcp dport map @fwd_tcp; dnat ip to udp dport map @fwd_udp; }
    chain postrouting { type nat hook postrouting priority 100; policy accept; oifname != "lo" masquerade; }
}
EOF
        fi
        nft -f /etc/nftables.conf; systemctl restart nftables
        echo -e "${gl_lv}防火墙已重置为: $type${gl_bai}"; read -p "..."
    }

    list_rules_ui() {
        echo -e "${gl_huang}=== 防火墙状态 ===${gl_bai}"
        echo -e "SSH Port: $(detect_ssh_port)"
        if nft list tables | grep -q "my_transit"; then t="my_transit"; st="local_tcp"; su="local_udp";
        elif nft list tables | grep -q "my_landing"; then t="my_landing"; st="allowed_tcp"; su="allowed_udp";
        else echo "未初始化"; return; fi
        
        echo "------------------------------------------------"
        local tcp=$(nft list set inet $t $st 2>/dev/null | grep 'elements =' | awk -F '{' '{print $2}' | awk -F '}' '{print $1}' | tr -d ' ')
        local udp=$(nft list set inet $t $su 2>/dev/null | grep 'elements =' | awk -F '{' '{print $2}' | awk -F '}' '{print $1}' | tr -d ' ')
        echo -e "放行 TCP: ${gl_kjlan}${tcp:-无}${gl_bai}"
        echo -e "放行 UDP: ${gl_kjlan}${udp:-无}${gl_bai}"
        
        if [ "$t" == "my_transit" ]; then
            echo "------------------------------------------------"
            echo "转发规则:"
            nft list map inet my_transit fwd_tcp | grep ':' | tr -d '\t,' | awk '{printf "TCP %-6s -> %s : %s\n", $1, $3, $5}'
            nft list map inet my_transit fwd_udp | grep ':' | tr -d '\t,' | awk '{printf "UDP %-6s -> %s : %s\n", $1, $3, $5}'
        fi
        echo "------------------------------------------------"
    }

    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#           Nftables 防火墙管理                #"
        echo -e "################################################${gl_bai}"
        if nft list tables | grep -q "my_transit"; then mode="transit"; table="my_transit"; set="local_tcp";
        elif nft list tables | grep -q "my_landing"; then mode="landing"; table="my_landing"; set="allowed_tcp";
        else mode="none"; fi
        
        echo -e "当前模式: ${gl_huang}$mode${gl_bai} | SSH端口: $(detect_ssh_port)"
        echo -e "------------------------------------------------"
        if [ "$mode" == "none" ]; then
            echo -e "${gl_lv} 1.${gl_bai} 初始化为: 落地机 (Landing)"
            echo -e "${gl_lv} 2.${gl_bai} 初始化为: 中转机 (Transit)"
        else
            echo -e "${gl_lv} 3.${gl_bai} 查看规则 (List Rules)"
            echo -e "${gl_lv} 4.${gl_bai} 放行端口 (Allow Port)"
            echo -e "${gl_lv} 5.${gl_bai} 删除端口 (Del Port)"
            if [ "$mode" == "transit" ]; then
                echo -e "${gl_kjlan} 6.${gl_bai} 添加转发 (Add Forward)"
                echo -e "${gl_kjlan} 7.${gl_bai} 删除转发 (Del Forward)"
            fi
            echo -e "${gl_hong} 8.${gl_bai} 重置防火墙 (Reset)"
        fi
        echo -e "${gl_hui} 0. 返回${gl_bai}"
        echo -e "------------------------------------------------"
        read -p "选项: " c
        case "$c" in
            1) init_firewall landing ;;
            2) init_firewall transit ;;
            3) list_rules_ui; read -p "..." ;;
            4) read -p "端口: " p; nft add element inet $table $set { $p }; nft add element inet $table ${set/tcp/udp} { $p }; nft list ruleset > /etc/nftables.conf; echo "OK"; sleep 1 ;;
            5) read -p "端口: " p; nft delete element inet $table $set { $p }; nft delete element inet $table ${set/tcp/udp} { $p }; nft list ruleset > /etc/nftables.conf; echo "OK"; sleep 1 ;;
            6) [ "$mode" == "transit" ] && read -p "本机端口: " lp && read -p "目标IP: " dip && read -p "目标端口: " dp && nft add element inet my_transit fwd_tcp { $lp : $dip . $dp } && nft add element inet my_transit fwd_udp { $lp : $dip . $dp } && nft list ruleset > /etc/nftables.conf && echo "OK"; sleep 1 ;;
            7) [ "$mode" == "transit" ] && read -p "本机端口: " lp && nft delete element inet my_transit fwd_tcp { $lp } && nft delete element inet my_transit fwd_udp { $lp } && nft list ruleset > /etc/nftables.conf && echo "OK"; sleep 1 ;;
            8) nft flush ruleset; echo "flush ruleset" > /etc/nftables.conf; echo "已重置"; sleep 1 ;;
            0) return ;;
        esac
    done
}

# ===== 功能模块: Fail2ban (完整版) =====
fail2ban_management() {
    install_f2b() {
        apt update && apt install fail2ban rsyslog -y
        systemctl enable --now rsyslog; touch /var/log/auth.log /var/log/fail2ban.log
        cat > /etc/fail2ban/jail.d/00-default-nftables.conf << EOF
[DEFAULT]
banaction = nftables-multiport
banaction_allports = nftables-allports
EOF
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
findtime = 600; maxretry = 5; backend = polling
[sshd]
enabled = true
port = $(ss -tlnp | grep 'sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -n 1 || echo 22)
filter = sshd
logpath = /var/log/auth.log
bantime = 10800
[recidive]
enabled = true
logpath = /var/log/fail2ban.log
filter = recidive
bantime = 259200
EOF
        systemctl restart fail2ban; echo -e "${gl_lv}Fail2ban 已安装${gl_bai}"; read -p "..."
    }

    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#             Fail2ban 防暴破管理                  #"
        echo -e "################################################${gl_bai}"
        if systemctl is-active --quiet fail2ban; then echo -e "状态: ${gl_lv}运行中${gl_bai}"; else echo -e "状态: ${gl_hong}停止${gl_bai}"; fi
        echo -e "------------------------------------------------"
        echo -e " 1. 安装/重置 (Install)"; echo -e " 2. 查看日志 (Log)"; echo -e " 3. 手动解封 IP (Unban)"; echo -e " 4. 卸载 (Uninstall)"; echo -e " 0. 返回"
        read -p "选项: " c
        case "$c" in
            1) install_f2b ;;
            2) echo "按回车退出..."; tail -f -n 20 /var/log/fail2ban.log & pid=$!; read -r; kill $pid ;;
            3) read -p "IP: " ip; fail2ban-client set sshd unbanip $ip; echo "已请求解封"; sleep 1 ;;
            4) apt purge fail2ban -y; rm -rf /etc/fail2ban; echo "已卸载"; read -p "..." ;;
            0) return ;;
        esac
    done
}

# ===== 功能模块: Xray 核心管理 (官方脚本 + 紧凑配置版) =====
xray_management() {
    ensure_port_open() {
        if command -v nft &>/dev/null; then
            if nft list tables | grep -q "my_landing"; then t="my_landing"; s="allowed_tcp"; su="allowed_udp";
            elif nft list tables | grep -q "my_transit"; then t="my_transit"; s="local_tcp"; su="local_udp"; else return; fi
            if ! nft list set inet $t $s 2>/dev/null | grep -q "52368"; then
                echo -e "${gl_huang}自动放行端口 52368...${gl_bai}"
                nft add element inet $t $s { 52368 }; nft add element inet $t $su { 52368 }; nft list ruleset > /etc/nftables.conf
            fi
        fi
    }

    install_xray() {
        echo -e "${gl_huang}正在调用官方脚本安装 Xray...${gl_bai}"
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
        echo -e "${gl_lv}安装完成。请执行选项 2 初始化配置。${gl_bai}"; read -p "..."
    }

    configure_reality() {
        if ! command -v xray &>/dev/null; then echo "请先安装 Xray"; sleep 1; return; fi
        ensure_port_open
        
        echo -e "${gl_huang}正在生成凭据...${gl_bai}"
        uuid=$(xray uuid)
        kp=$(xray x25519)
        pri=$(echo "$kp" | grep "Private key" | awk '{print $NF}')
        pub=$(echo "$kp" | grep "Public key" | awk '{print $NF}')
        sid=$(openssl rand -hex 4)
        
        # 紧凑版配置
        cat > /usr/local/etc/xray/config.json << EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": 52368, "protocol": "vless",
      "settings": { "clients": [ { "id": "$uuid", "flow": "xtls-rprx-vision" } ], "decryption": "none" },
      "streamSettings": {
        "network": "tcp", "security": "reality",
        "realitySettings": {
          "dest": "www.microsoft.com:443", "serverNames": [ "www.microsoft.com", "microsoft.com" ],
          "privateKey": "$pri", "shortIds": [ "$sid" ]
        }
      },
      "sniffing": { "enabled": true, "destOverride": [ "http", "tls", "quic" ] }
    }
  ],
  "outbounds": [ { "protocol": "freedom", "tag": "direct" }, { "protocol": "blackhole", "tag": "block" } ],
  "routing": { "domainStrategy": "IPIfNonMatch", "rules": [ { "type": "field", "ip": [ "geoip:private" ], "outboundTag": "block" } ] }
}
EOF
        systemctl restart xray
        ip=$(curl -s https://ipinfo.io/ip)
        
        echo -e "------------------------------------------------"
        echo -e "${gl_kjlan}Xray Reality 配置完成${gl_bai}"
        echo -e "地址: ${gl_bai}$ip${gl_bai}"
        echo -e "端口: ${gl_bai}52368${gl_bai}"
        echo -e "UUID: ${gl_bai}$uuid${gl_bai}"
        echo -e "Public Key: ${gl_bai}$pub${gl_bai}"
        echo -e "Short ID:   ${gl_bai}$sid${gl_bai}"
        echo -e "------------------------------------------------"
        echo -e "链接: ${gl_lv}vless://$uuid@$ip:52368?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=$pub&sid=$sid&type=tcp&headerType=none#Xray-Reality${gl_bai}"
        echo -e "------------------------------------------------"
        read -p "按回车继续..."
    }

    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#           Xray 核心服务管理 (Reality)        #"
        echo -e "################################################${gl_bai}"
        if systemctl is-active --quiet xray; then echo -e "状态: ${gl_lv}运行中${gl_bai}"; else echo -e "状态: ${gl_hong}停止/未安装${gl_bai}"; fi
        echo "------------------------------------------------"
        echo -e "${gl_lv} 1.${gl_bai} 安装/升级 (Official Script)"
        echo -e "${gl_lv} 2.${gl_bai} 初始化配置 (Reality-Vision)"
        echo "------------------------------------------------"
        echo -e "${gl_huang} 3.${gl_bai} 查看日志"
        echo -e "${gl_huang} 4.${gl_bai} 重启服务"
        echo -e "${gl_huang} 5.${gl_bai} 停止服务"
        echo "------------------------------------------------"
        echo -e "${gl_hong} 6.${gl_bai} 卸载 Xray"
        echo -e "${gl_hui} 0. 返回主菜单${gl_bai}"
        echo "------------------------------------------------"
        read -p "选项: " c
        case "$c" in
            1) install_xray ;;
            2) configure_reality ;;
            3) echo "回车退出..."; journalctl -u xray -n 20 -f & pid=$!; read -r; kill $pid ;;
            4) systemctl restart xray; echo "已重启"; sleep 1 ;;
            5) systemctl stop xray; echo "已停止"; sleep 1 ;;
            6) bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove; read -p "..." ;;
            0) return ;;
        esac
    done
}

# ===== 功能 1: 系统信息 (完整版) =====
linux_info() {
    clear
    echo -e "${gl_huang}正在采集系统信息...${gl_bai}"
    ip_address
    output_status
    local cpu_info=$(lscpu | awk -F': +' '/Model name:/ {print $2; exit}')
    local load=$(uptime | awk '{print $(NF-2), $(NF-1), $NF}')
    local mem_info=$(free -b | awk 'NR==2{printf "%.2f/%.2fM (%.2f%%)", $3/1024/1024, $2/1024/1024, $3*100/$2}')
    local swap_info=$(free -m | awk 'NR==3{used=$3; total=$2; if (total == 0) {percentage=0} else {percentage=used*100/total}; printf "%dM/%dM (%d%%)", used, total, percentage}')
    local disk_info=$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}')
    local runtime=$(cat /proc/uptime | awk -F. '{run_days=int($1 / 86400);run_hours=int(($1 % 86400) / 3600);run_minutes=int(($1 % 3600) / 60); if (run_days > 0) printf("%d天 ", run_days); if (run_hours > 0) printf("%d时 ", run_hours); printf("%d分\n", run_minutes)}')
    
    echo ""
    echo -e "${gl_lv}系统信息概览${gl_bai}"
    echo -e "------------------------------------------------"
    echo -e "主机名:     $(uname -n)"
    echo -e "系统版本:   $(grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | tr -d '"')"
    echo -e "CPU:        $cpu_info ($(nproc)核)"
    echo -e "占用/负载:  $(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}')% / $load"
    echo -e "物理内存:   $mem_info"
    echo -e "虚拟内存:   $swap_info"
    echo -e "硬盘占用:   $disk_info"
    echo -e "流量(R/T):  $rx / $tx"
    echo -e "------------------------------------------------"
    echo -e "IPv4地址:   ${ipv4_address}"
    [ -n "$ipv6_address" ] && echo -e "IPv6地址:   ${ipv6_address}"
    echo -e "地理位置:   $isp_info"
    echo -e "系统时间:   $(date "+%Y-%m-%d %H:%M:%S") ($(current_timezone))"
    echo -e "运行时长:   $runtime"
    echo
    echo "按回车返回..."
    read -r
}

# ===== 功能 2: 系统更新 =====
linux_update() {
    echo -e "${gl_huang}正在更新系统...${gl_bai}"
    apt update -y && apt full-upgrade -y
    if [ -f /var/run/reboot-required ]; then
        read -p "内核更新需要重启，是否重启? (y/n): " r
        [[ "$r" =~ ^[yY]$ ]] && reboot
    else
        echo -e "${gl_lv}更新完成${gl_bai}"; read -p "..."
    fi
}

# ===== 功能 3: 系统清理 =====
linux_clean() {
    echo -e "${gl_huang}正在清理垃圾...${gl_bai}"
    apt autoremove --purge -y; apt clean -y; apt autoclean -y
    journalctl --rotate; journalctl --vacuum-time=1s
    find /tmp -type f -atime +10 -delete 2>/dev/null
    echo -e "${gl_lv}清理完成${gl_bai}"; read -p "..."
}

# ===== 功能 9: 更新脚本 =====
update_script() {
    echo -e "${gl_huang}更新脚本...${gl_bai}"
    sh_url="https://raw.githubusercontent.com/OPPO518/sh/main/x.sh"
    if curl -sS -o /usr/local/bin/x "$sh_url"; then chmod +x /usr/local/bin/x; echo -e "${gl_lv}成功${gl_bai}"; exec /usr/local/bin/x; else echo "失败"; fi
}

# ===== 主菜单 =====
main_menu() {
    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#                                              #"
        echo -e "#            Debian VPS 极简运维工具箱         #"
        echo -e "#                                              #"
        echo -e "################################################${gl_bai}"
        echo -e "${gl_huang}版本: 1.7 (Xray Full Edition)${gl_bai}"
        echo -e "------------------------------------------------"
        echo -e "${gl_lv} 1.${gl_bai} 系统初始化 (System Init) ${gl_hong}[新机必点]${gl_bai}"
        echo -e "${gl_lv} 2.${gl_bai} 虚拟内存管理 (Swap Manager)"
        echo -e "------------------------------------------------"
        echo -e "${gl_kjlan} 3.${gl_bai} 防火墙/中转管理 (Nftables) ${gl_hong}[核心]${gl_bai}"
        echo -e "${gl_kjlan} 4.${gl_bai} 防暴力破解管理 (Fail2ban) ${gl_hong}[安全]${gl_bai}"
        echo -e "${gl_kjlan} 8.${gl_bai} 核心代理服务 (Xray-core) ${gl_hong}[Reality]${gl_bai}"
        echo -e "------------------------------------------------"
        echo -e "${gl_lv} 5.${gl_bai} 系统信息查询 (System Info)"
        echo -e "${gl_lv} 6.${gl_bai} 系统更新 (Update Only)"
        echo -e "${gl_lv} 7.${gl_bai} 系统清理 (Clean Junk)"
        echo -e "------------------------------------------------"
        echo -e "${gl_kjlan} 9.${gl_bai} 更新脚本 (Update Script)"
        echo -e "${gl_hong} 0.${gl_bai} 退出 (Exit)"
        echo -e "------------------------------------------------"
        
        read -p " 请输入选项 [0-9]: " choice

        case "$choice" in
            1) system_initialize ;;
            2) swap_management ;;
            3) nftables_management ;;
            4) fail2ban_management ;;
            8) xray_management ;;
            5) linux_info ;;
            6) linux_update ;;
            7) linux_clean ;;
            9) update_script ;;
            0) exit 0 ;;
            *) echo -e "${gl_hong}无效的选项！${gl_bai}"; sleep 1 ;;
        esac
    done
}

# 检查权限
[ "$(id -u)" != "0" ] && { echo "请使用 root 运行!"; exit 1; }

main_menu
