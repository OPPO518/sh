#!/bin/bash

# ===== 自我安装与环境检查 =====
current_script=$(readlink -f "$0")
target_path="/usr/local/bin/x"
if [ "$current_script" != "$target_path" ]; then
    cp -f "$current_script" "$target_path"
    chmod +x "$target_path"
fi

# ===== 全局颜色变量 =====
gl_hong='\033[31m'
gl_lv='\033[32m'
gl_huang='\033[33m'
gl_lan='\033[34m'
gl_bai='\033[0m'
gl_zi='\033[35m'
gl_kjlan='\033[96m'
gl_hui='\e[37m'

# ===== 全局辅助: 获取国旗 Emoji (优化: 全局定义，减少冗余) =====
get_flag_local() {
    case "$1" in
        CN) echo "🇨🇳" ;; HK) echo "🇭🇰" ;; MO) echo "🇲🇴" ;; TW) echo "🇹🇼" ;;
        US) echo "🇺🇸" ;; JP) echo "🇯🇵" ;; KR) echo "🇰🇷" ;; SG) echo "🇸🇬" ;;
        RU) echo "🇷🇺" ;; DE) echo "🇩🇪" ;; GB) echo "🇬🇧" ;; FR) echo "🇫🇷" ;;
        NL) echo "🇳🇱" ;; CA) echo "🇨🇦" ;; AU) echo "🇦🇺" ;; IN) echo "🇮🇳" ;;
        TH) echo "🇹🇭" ;; VN) echo "🇻🇳" ;; MY) echo "🇲🇾" ;; ID) echo "🇮🇩" ;;
        BR) echo "🇧🇷" ;; ZA) echo "🇿🇦" ;; IT) echo "🇮🇹" ;; ES) echo "🇪🇸" ;;
        *) echo "🌐" ;; 
    esac
}

# ===== 辅助函数: IP信息获取 =====
ip_address() {
    get_public_ip() { curl -s https://ipinfo.io/ip && echo; }
    get_local_ip() { ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[^ ]+' || hostname -I 2>/dev/null | awk '{print $1}'; }
    public_ip=$(get_public_ip)
    isp_info=$(curl -s --max-time 3 http://ipinfo.io/org)
    if echo "$isp_info" | grep -Eiq 'mobile|unicom|telecom'; then ipv4_address=$(get_local_ip); else ipv4_address="$public_ip"; fi
    ipv6_address=$(curl -s --max-time 1 https://v6.ipinfo.io/ip && echo)
    # 增加国家代码获取，供全局使用
    country_code=$(curl -s --max-time 3 https://ipinfo.io/country | tr -d '\n')
    flag=$(get_flag_local "$country_code")
}

# ===== 辅助函数: 网络流量统计 =====
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

# ===== 辅助函数: 时区检测 =====
current_timezone() {
    if grep -q 'Alpine' /etc/issue; then date +"%Z %z"; else timedatectl | grep "Time zone" | awk '{print $3}'; fi
}

# ===== 模块 1: 系统初始化 (v1.6 逻辑) =====
system_initialize() {
    clear
    echo -e "${gl_kjlan}################################################"
    echo -e "#            系统初始化配置 (System Init)        #"
    echo -e "################################################${gl_bai}"
    
    local os_ver=""
    if grep -q "bullseye" /etc/os-release; then os_ver="11"; echo -e "当前系统: ${gl_huang}Debian 11 (Bullseye)${gl_bai}";
    elif grep -q "bookworm" /etc/os-release; then os_ver="12"; echo -e "当前系统: ${gl_huang}Debian 12 (Bookworm)${gl_bai}";
    else echo -e "${gl_hong}错误: 本脚本仅支持 Debian 11 或 12 系统！${gl_bai}"; read -p "按回车返回..."; return; fi
    
    echo -e "${gl_hui}* 包含换源、BBR、时区及落地/中转环境配置${gl_bai}"
    echo -e "------------------------------------------------"
    echo -e "请设定当前 VPS 的业务角色："
    echo -e "${gl_lv} 1.${gl_bai} 落地机 (Landing)  -> [关闭转发 | 极简安全]"
    echo -e "${gl_lv} 2.${gl_bai} 中转机 (Transit)  -> [开启转发 | 路由优化]"
    echo -e "${gl_hui} 0. 返回主菜单${gl_bai}"
    echo -e "------------------------------------------------"
    read -p "请输入选项 [0-2]: " role_choice
    if [ "$role_choice" == "0" ]; then return; fi

    echo -e "${gl_kjlan}>>> 正在执行初始化...${gl_bai}"
    
    [ -f /etc/apt/sources.list ] && mv /etc/apt/sources.list /etc/apt/sources.list.bak_$(date +%F)
    if [ "$os_ver" == "11" ]; then
        echo -e "deb http://deb.debian.org/debian bullseye main contrib non-free
deb http://deb.debian.org/debian bullseye-updates main contrib non-free
deb http://security.debian.org/debian-security bullseye-security main contrib non-free
deb http://archive.debian.org/debian bullseye-backports main contrib non-free" > /etc/apt/sources.list
    else
        echo -e "deb http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian-security/ bookworm-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian/ bookworm-updates main contrib non-free non-free-firmware
deb http://deb.debian.org/debian/ bookworm-backports main contrib non-free non-free-firmware" > /etc/apt/sources.list
    fi

    export DEBIAN_FRONTEND=noninteractive
    apt update && apt upgrade -y -o Dpkg::Options::="--force-confold"
    apt install curl wget systemd-timesyncd socat cron rsync unzip -y

    rm -f /etc/sysctl.d/99-vps-optimize.conf
    cat > /etc/sysctl.d/99-vps-optimize.conf << EOF
# BBR
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
# 基础优化
net.ipv4.icmp_echo_ignore_all=0
net.netfilter.nf_conntrack_max=1000000
net.nf_conntrack_max=1000000
EOF
    
    if [ "$role_choice" == "1" ]; then
        echo "net.ipv4.ip_forward=0" >> /etc/sysctl.d/99-vps-optimize.conf
        echo "net.ipv6.conf.all.forwarding=0" >> /etc/sysctl.d/99-vps-optimize.conf
    else
        modprobe nft_nat 2>/dev/null; modprobe br_netfilter 2>/dev/null
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.d/99-vps-optimize.conf
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-vps-optimize.conf
        echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.d/99-vps-optimize.conf
    fi
    sysctl --system
    
    timedatectl set-timezone Asia/Shanghai
    systemctl enable --now systemd-timesyncd
    
    echo -e "${gl_lv}初始化完成！${gl_bai}"
    if [ -f /var/run/reboot-required ]; then
        echo -e "${gl_hong}!!! 检测到内核更新，必须重启 !!!${gl_bai}"
        read -p "是否立即重启? (y/n): " rb
        [[ "$rb" =~ ^[yY]$ ]] && reboot
    else
        read -p "按回车返回..."
    fi
}

# ===== 模块 2: Swap 管理 (v1.6 逻辑) =====
swap_management() {
    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#            Swap 虚拟内存管理                     #"
        echo -e "################################################${gl_bai}"
        local swap_total=$(free -m | grep Swap | awk '{print $2}')
        if [ "$swap_total" -eq 0 ]; then
             echo -e "当前状态: ${gl_hong}未启用${gl_bai}"
        else
             echo -e "当前状态: ${gl_lv}已启用${gl_bai} | 大小: ${gl_huang}${swap_total}MB${gl_bai}"
        fi
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
                    echo -e "${gl_huang}正在处理...${gl_bai}"
                    swapoff -a 2>/dev/null; rm -f /swapfile; sed -i '/swapfile/d' /etc/fstab
                    dd if=/dev/zero of=/swapfile bs=1M count=$s status=progress
                    chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile
                    echo '/swapfile none swap sw 0 0' >> /etc/fstab
                    echo -e "${gl_lv}成功${gl_bai}"; read -p "..." 
                fi ;;
            2) 
                echo -e "${gl_huang}正在卸载...${gl_bai}"
                swapoff -a; rm -f /swapfile; sed -i '/swapfile/d' /etc/fstab; echo -e "${gl_lv}已删除${gl_bai}"; read -p "..." ;;
            0) return ;;
        esac
    done
}

# ===== 模块 3: Nftables 防火墙 (v1.6 逻辑 + 修复菜单Bug) =====
nftables_management() {
    detect_ssh() { ss -tlnp | grep 'sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -n 1 || echo 22; }
    
    init_fw() {
        local type=$1; local port=$(detect_ssh)
        echo -e "${gl_huang}清理环境...${gl_bai}"
        ufw disable 2>/dev/null; apt purge ufw -y 2>/dev/null
        
        if [ "$type" == "landing" ]; then
            sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1
        else
            sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
        fi

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
        echo -e "SSH Port: ${gl_lv}$(detect_ssh)${gl_bai}"
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
        if nft list tables | grep -q "my_transit"; then mode="Transit"; table="my_transit"; set="local_tcp";
        elif nft list tables | grep -q "my_landing"; then mode="Landing"; table="my_landing"; set="allowed_tcp";
        else mode="None"; fi
        
        echo -e "模式: ${gl_huang}$mode${gl_bai} | SSH端口: $(detect_ssh)"
        echo -e "------------------------------------------------"
        if [ "$mode" == "None" ]; then
            echo -e "${gl_lv} 1.${gl_bai} 初始化为: 落地机 (Landing)"
            echo -e "${gl_lv} 2.${gl_bai} 初始化为: 中转机 (Transit)"
        else
            echo -e "${gl_lv} 3.${gl_bai} 查看规则 (List Rules)"
            echo -e "${gl_lv} 4.${gl_bai} 放行端口 (Allow Port)"
            echo -e "${gl_lv} 5.${gl_bai} 删除端口 (Del Port)"
            if [ "$mode" == "Transit" ]; then
                echo -e "${gl_kjlan} 6.${gl_bai} 添加转发 (Add Forward)"
                echo -e "${gl_kjlan} 7.${gl_bai} 删除转发 (Del Forward)"
            fi
            echo -e "${gl_hong} 8.${gl_bai} 重置防火墙 (Reset)"
        fi
        echo -e "${gl_hui} 0. 返回${gl_bai}"
        echo -e "------------------------------------------------"
        read -p "选项: " c
        case "$c" in
            # [修复]: 增加状态判断，防止误触不可见菜单
            1) if [ "$mode" == "None" ]; then init_fw landing; else echo -e "${gl_hong}请先重置!${gl_bai}"; sleep 1; fi ;;
            2) if [ "$mode" == "None" ]; then init_fw transit; else echo -e "${gl_hong}请先重置!${gl_bai}"; sleep 1; fi ;;
            3) list_rules_ui; read -p "..." ;;
            4) read -p "端口: " p; nft add element inet $table $set { $p }; nft add element inet $table ${set/tcp/udp} { $p }; nft list ruleset > /etc/nftables.conf; echo "OK"; sleep 1 ;;
            5) read -p "端口: " p; nft delete element inet $table $set { $p }; nft delete element inet $table ${set/tcp/udp} { $p }; nft list ruleset > /etc/nftables.conf; echo "OK"; sleep 1 ;;
            6) [ "$mode" == "Transit" ] && read -p "本机端口: " lp && read -p "目标IP: " dip && read -p "目标端口: " dp && nft add element inet my_transit fwd_tcp { $lp : $dip . $dp } && nft add element inet my_transit fwd_udp { $lp : $dip . $dp } && nft list ruleset > /etc/nftables.conf && echo "OK"; sleep 1 ;;
            7) [ "$mode" == "Transit" ] && read -p "本机端口: " lp && nft delete element inet my_transit fwd_tcp { $lp } && nft delete element inet my_transit fwd_udp { $lp } && nft list ruleset > /etc/nftables.conf && echo "OK"; sleep 1 ;;
            8) nft flush ruleset; echo "flush ruleset" > /etc/nftables.conf; 
               if systemctl is-active --quiet fail2ban; then systemctl restart fail2ban; fi
               echo "已重置"; read -p "..." ;;
            0) return ;;
        esac
    done
}

# ===== 模块 4: Fail2ban (v1.6 逻辑) =====
fail2ban_management() {
    install_f2b() {
        echo -e "${gl_huang}安装 Fail2ban...${gl_bai}"
        read -p "请输入白名单IP (空格分隔): " wl
        ignore="127.0.0.1/8 ::1 $wl"
        ssh_port=$(ss -tlnp | grep 'sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -n 1 || echo 22)
        
        apt update && apt install fail2ban rsyslog -y
        systemctl enable --now rsyslog; touch /var/log/auth.log /var/log/fail2ban.log
        
        cat > /etc/fail2ban/jail.d/00-default-nftables.conf << EOF
[DEFAULT]
banaction = nftables-multiport
banaction_allports = nftables-allports
chain = input
EOF
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
ignoreip = $ignore
findtime = 600; maxretry = 5; backend = polling
[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
bantime = 10800
[recidive]
enabled = true
logpath = /var/log/fail2ban.log
filter = recidive
bantime = 259200
EOF
        systemctl restart fail2ban; echo -e "${gl_lv}已安装${gl_bai}"; read -p "..."
    }

    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#             Fail2ban 防暴破管理                  #"
        echo -e "################################################${gl_bai}"
        if systemctl is-active --quiet fail2ban; then echo -e "状态: ${gl_lv}运行中${gl_bai}"; else echo -e "状态: ${gl_hong}停止${gl_bai}"; fi
        echo -e "------------------------------------------------"
        echo " 1. 安装/重置 (Install)"
        echo " 2. 查看日志 (Log)"
        echo " 3. 手动解封 IP (Unban)"
        echo " 4. 卸载 (Uninstall)"
        echo " 0. 返回"
        read -p "选项: " c
        case "$c" in
            1) install_f2b ;;
            2) echo -e "${gl_huang}按回车退出...${gl_bai}"; tail -f -n 20 /var/log/fail2ban.log & pid=$!; read -r; kill $pid; wait $pid 2>/dev/null ;;
            3) read -p "IP: " ip; fail2ban-client set sshd unbanip $ip; fail2ban-client set recidive unbanip $ip; echo "OK"; sleep 1 ;;
            4) apt purge fail2ban -y; rm -rf /etc/fail2ban; nft delete table inet f2b-table 2>/dev/null; echo "已卸载"; read -p "..." ;;
            0) return ;;
        esac
    done
}

# ===== 模块 8A: Xray 管理 (收据模式 + 自动端口) =====
xray_management() {
    BIN_PATH="/usr/local/bin/xray"
    CONF_DIR="/usr/local/etc/xray"
    INFO_FILE="${CONF_DIR}/info.txt"

    ensure_port_open() {
        local port="$1"
        if command -v nft &>/dev/null; then
            if nft list tables | grep -q "my_landing"; then t="my_landing"; s="allowed_tcp"; su="allowed_udp";
            elif nft list tables | grep -q "my_transit"; then t="my_transit"; s="local_tcp"; su="local_udp"; else return; fi
            if ! nft list set inet $t $s 2>/dev/null | grep -q "$port"; then
                echo -e "${gl_huang}自动放行端口 $port...${gl_bai}"
                nft add element inet $t $s { $port }; nft add element inet $t $su { $port }
                nft list ruleset > /etc/nftables.conf
            fi
        fi
    }

    install_xray() {
        echo -e "${gl_huang}调用官方脚本安装 (Install Latest)...${gl_bai}"
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root
        if [ $? -eq 0 ]; then
            echo -e "${gl_lv}安装成功！${gl_bai}"; $BIN_PATH version | head -n 1
        else
            echo -e "${gl_hong}安装失败 (网络问题)${gl_bai}"; 
        fi
        read -p "按回车继续..."
    }

    configure_reality() {
        [ ! -f "$BIN_PATH" ] && { echo "请先安装 Xray"; sleep 1; return; }
        
        local port=$(shuf -i 20000-65000 -n 1)
        ensure_port_open "$port"
        echo -e "${gl_huang}生成配置中...${gl_bai}"
        
        uuid=$($BIN_PATH uuid)
        kp=$($BIN_PATH x25519)
        pri=$(echo "$kp" | grep -i "Private" | cut -d: -f2 | tr -d '[:space:]')
        pub=$(echo "$kp" | grep -i "Public" | cut -d: -f2 | tr -d '[:space:]')
        [ -z "$pub" ] && pub=$(echo "$kp" | grep -i "Password" | cut -d: -f2 | tr -d '[:space:]')
        sid=$(openssl rand -hex 8)
        
        mkdir -p $CONF_DIR
        cat > ${CONF_DIR}/config.json << EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": $port, "protocol": "vless",
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
        echo -e "${gl_huang}保存配置收据...${gl_bai}"
        local ip=$(curl -s --max-time 3 https://ipinfo.io/ip)
        local code=$(curl -s --max-time 3 https://ipinfo.io/country | tr -d '\n')
        local flag=$(get_flag_local "$code")
        local link="vless://$uuid@$ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=$pub&sid=$sid&type=tcp&headerType=none#${flag}Xray-Reality"

        echo -e "------------------------------------------------
${gl_kjlan}>>> 客户端连接信息 (Xray-core) <<<${gl_bai}
地址 (Address): ${gl_bai}$ip${gl_bai}
地区 (Region):  ${gl_bai}$code $flag${gl_bai}
端口 (Port):    ${gl_bai}$port${gl_bai}
用户ID (UUID):  ${gl_bai}$uuid${gl_bai}
公钥 (Public):  ${gl_bai}$pub${gl_bai}
Short ID:       ${gl_bai}$sid${gl_bai}
------------------------------------------------
${gl_kjlan}快速导入链接:${gl_bai}
${gl_lv}$link${gl_bai}
------------------------------------------------" > $INFO_FILE
        
        systemctl restart xray
        view_config
    }

    view_config() {
        if [ -f "$INFO_FILE" ]; then clear; cat $INFO_FILE; else echo -e "${gl_hong}未找到配置，请先初始化${gl_bai}"; fi
        [ "${FUNCNAME[1]}" != "configure_reality" ] && read -p "按回车返回..."
    }

    uninstall_xray() {
        echo -e "${gl_huang}调用官方脚本卸载...${gl_bai}"
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
        rm -rf $CONF_DIR
        echo "已卸载"; read -p "..."
    }

    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#         Xray 核心管理 (Official Standard)    #"
        echo -e "################################################${gl_bai}"
        if systemctl is-active --quiet xray; then v=$($BIN_PATH version 2>/dev/null | head -n 1 | awk '{print $2}'); echo -e "状态: ${gl_lv}● 运行中${gl_bai} (Ver: ${v:-未知})"; else echo -e "状态: ${gl_hong}● 已停止${gl_bai}"; fi
        echo -e "------------------------------------------------"
        echo -e "${gl_lv} 1.${gl_bai} 安装/更新 (Install Latest)"
        echo -e "${gl_lv} 2.${gl_bai} 初始化配置 (Reset Config)"
        echo -e "${gl_huang} 3.${gl_bai} 查看当前配置 (View Info)"
        echo -e "------------------------------------------------"
        echo -e " 4. 查看日志 (Snapshot)"
        echo -e " 5. 重启服务 (Restart)"
        echo -e " 6. 停止服务 (Stop)"
        echo -e "------------------------------------------------"
        echo -e "${gl_hong} 9.${gl_bai} 彻底卸载 (Uninstall)"
        echo -e "${gl_hui} 0.${gl_bai} 返回上级菜单"
        echo -e "------------------------------------------------"
        read -p "选项: " c
        case "$c" in
            1) install_xray ;;
            2) configure_reality ;;
            3) view_config ;;
            4) echo -e "${gl_huang}回车退出监控...${gl_bai}"; journalctl -u xray -n 50 -f & pid=$!; read -r; kill $pid; wait $pid 2>/dev/null ;;
            5) systemctl restart xray; echo "已重启"; sleep 1 ;;
            6) systemctl stop xray; echo "已停止"; sleep 1 ;;
            9) uninstall_xray ;;
            0) return ;;
            *) echo "无效选项" ;;
        esac
    done
}

# ===== 模块 8B: Sing-box 管理 =====
singbox_management() {
    BIN_PATH="/usr/bin/sing-box"
    CONF_DIR="/etc/sing-box"
    INFO_FILE="${CONF_DIR}/info.txt"

    ensure_port_open() {
        local port="$1"
        if command -v nft &>/dev/null; then
            if nft list tables | grep -q "my_landing"; then t="my_landing"; s="allowed_tcp"; su="allowed_udp";
            elif nft list tables | grep -q "my_transit"; then t="my_transit"; s="local_tcp"; su="local_udp"; else return; fi
            if ! nft list set inet $t $s 2>/dev/null | grep -q "$port"; then
                echo -e "${gl_huang}自动放行端口 $port...${gl_bai}"
                nft add element inet $t $s { $port }; nft add element inet $t $su { $port }
                nft list ruleset > /etc/nftables.conf
            fi
        fi
    }

    get_ver() {
        local tag=$(curl -sL --max-time 5 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | grep '"tag_name":' | head -n 1 | cut -d '"' -f 4)
        [ -z "$tag" ] && echo "v1.12.13" || echo "$tag"
    }

    install_sb() {
        echo -e "${gl_huang}检查架构...${gl_bai}"
        local arch=$(uname -m); local sb_arch=""
        case "$arch" in x86_64) sb_arch="amd64";; aarch64) sb_arch="arm64";; *) echo "不支持"; return;; esac

        local version=$(get_ver)
        echo -e "最新版本: ${gl_lv}${version}${gl_bai}"
        local ver_num=${version#v} 
        local url="https://github.com/SagerNet/sing-box/releases/download/${version}/sing-box_${ver_num}_linux_${sb_arch}.deb"

        echo -e "${gl_kjlan}下载 .deb...${gl_bai}"
        if curl -L -o /tmp/sb.deb "$url"; then
            echo -e "${gl_huang}安装/升级...${gl_bai}"
            if command -v sing-box &>/dev/null; then
                # 安全升级
                ar x /tmp/sb.deb data.tar.xz --output /tmp/
                tar -xf /tmp/data.tar.xz -C /tmp/ ./usr/bin/sing-box
                systemctl stop sing-box
                cp -f /tmp/usr/bin/sing-box /usr/bin/sing-box; chmod +x /usr/bin/sing-box
                systemctl restart sing-box
                rm -f /tmp/sb.deb /tmp/data.tar.xz /tmp/usr/bin/sing-box; rm -rf /tmp/usr
                echo -e "${gl_lv}升级完成${gl_bai}"
            else
                # 首次安装
                apt install /tmp/sb.deb -y; rm -f /tmp/sb.deb
                systemctl daemon-reload; systemctl enable sing-box; systemctl restart sing-box 2>/dev/null
                echo -e "${gl_lv}安装完成${gl_bai}"
            fi
            sing-box version | head -n 1
        else
            echo -e "${gl_hong}下载失败${gl_bai}"
        fi
        read -p "按回车继续..."
    }

    config_sb() {
        if ! command -v sing-box &>/dev/null; then echo -e "${gl_hong}请先安装!${gl_bai}"; sleep 1; return; fi

        local port=$(shuf -i 20000-65000 -n 1)
        ensure_port_open "$port"
        echo -e "${gl_huang}生成配置...${gl_bai}"
        
        local uuid=$(sing-box generate uuid)
        local kp=$(sing-box generate reality-keypair)
        local pri=$(echo "$kp" | grep "PrivateKey" | awk '{print $2}')
        local pub=$(echo "$kp" | grep "PublicKey" | awk '{print $2}')
        local sid=$(openssl rand -hex 8)
        
        cat > ${CONF_DIR}/config.json << EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "vless", "tag": "vless-in", "listen": "::", "listen_port": $port,
      "users": [ { "uuid": "$uuid", "flow": "xtls-rprx-vision" } ],
      "tls": {
        "enabled": true, "server_name": "www.microsoft.com",
        "reality": { "enabled": true, "handshake": { "server": "www.microsoft.com", "server_port": 443 }, "private_key": "$pri", "short_id": [ "$sid" ] }
      }
    }
  ]
}
EOF
        if ! sing-box check -c ${CONF_DIR}/config.json >/dev/null; then echo -e "${gl_hong}配置生成错误${gl_bai}"; read -p "..."; return; fi

        echo -e "${gl_huang}保存连接信息...${gl_bai}"
        local ip=$(curl -s --max-time 3 https://ipinfo.io/ip)
        local code=$(curl -s --max-time 3 https://ipinfo.io/country | tr -d '\n')
        local flag=$(get_flag_local "$code")
        local link="vless://$uuid@$ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=$pub&sid=$sid&type=tcp&headerType=none#${flag}SingBox-Reality"

        echo -e "------------------------------------------------
${gl_kjlan}>>> 客户端连接信息 (Sing-box) <<<${gl_bai}
地址 (Address): ${gl_bai}$ip${gl_bai}
地区 (Region):  ${gl_bai}$code $flag${gl_bai}
端口 (Port):    ${gl_bai}$port${gl_bai}
用户ID (UUID):  ${gl_bai}$uuid${gl_bai}
公钥 (Public):  ${gl_bai}$pub${gl_bai}
Short ID:       ${gl_bai}$sid${gl_bai}
------------------------------------------------
${gl_kjlan}快速导入链接:${gl_bai}
${gl_lv}$link${gl_bai}
------------------------------------------------" > $INFO_FILE
        systemctl restart sing-box
        view_sb
    }

    view_sb() {
        if [ -f "$INFO_FILE" ]; then clear; cat $INFO_FILE; else echo -e "${gl_hong}未找到配置，请先初始化${gl_bai}"; fi
        [ "${FUNCNAME[1]}" != "config_sb" ] && read -p "按回车返回..."
    }

    uninstall_sb() {
        echo -e "${gl_hong}警告: 将删除 Sing-box 程序及配置！${gl_bai}"
        read -p "确认? (y/n): " c
        if [[ "$c" == "y" ]]; then
            echo -e "${gl_huang}卸载中...${gl_bai}"
            systemctl stop sing-box; apt purge sing-box -y; apt autoremove -y; rm -rf $CONF_DIR /usr/bin/sing-box
            echo -e "${gl_lv}已卸载${gl_bai}"
        fi
        read -p "按回车继续..."
    }

    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#           Sing-box 核心管理 (Reality)        #"
        echo -e "################################################${gl_bai}"
        if systemctl is-active --quiet sing-box; then v=$($BIN_PATH version | head -n 1 | awk '{print $3}'); echo -e "状态: ${gl_lv}● 运行中${gl_bai} (Ver: $v)"; else echo -e "状态: ${gl_hong}● 已停止${gl_bai}"; fi
        echo -e "------------------------------------------------"
        echo -e "${gl_lv} 1.${gl_bai} 安装/升级 (Install Latest)"
        echo -e "${gl_lv} 2.${gl_bai} 初始化配置 (Reset Config)"
        echo -e "${gl_huang} 3.${gl_bai} 查看当前配置 (View Info)"
        echo -e "------------------------------------------------"
        echo -e " 4. 查看日志 (Snapshot)"
        echo -e " 5. 重启服务 (Restart)"
        echo -e " 6. 停止服务 (Stop)"
        echo -e "------------------------------------------------"
        echo -e "${gl_hong} 9.${gl_bai} 彻底卸载 (Uninstall)"
        echo -e "${gl_hui} 0.${gl_bai} 返回上级菜单"
        echo -e "------------------------------------------------"
        read -p "选项: " c
        case "$c" in
            1) install_sb ;;
            2) config_sb ;;
            3) view_sb ;;
            4) echo -e "${gl_huang}回车退出监控...${gl_bai}"; journalctl -u sing-box -n 50 -f & pid=$!; read -r; kill $pid; wait $pid 2>/dev/null ;;
            5) systemctl restart sing-box; echo -e "${gl_lv}已重启${gl_bai}"; sleep 1 ;;
            6) systemctl stop sing-box; echo -e "${gl_hong}已停止${gl_bai}"; sleep 1 ;;
            9) uninstall_sb ;;
            0) return ;;
            *) echo "无效选项" ;;
        esac
    done
}

# ===== 模块 8: 代理选择菜单 =====
proxy_menu() {
    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#            代理服务选择 (Proxy Selection)    #"
        echo -e "################################################${gl_bai}"
        echo -e "${gl_hui}请选择您要管理的核心内核：${gl_bai}"
        echo -e "------------------------------------------------"
        if systemctl is-active --quiet xray; then echo -e "${gl_lv} 1.${gl_bai} Xray-core     ${gl_lv}[运行中]${gl_bai}"; else echo -e "${gl_lv} 1.${gl_bai} Xray-core     ${gl_hui}[未运行]${gl_bai}"; fi
        if systemctl is-active --quiet sing-box; then echo -e "${gl_kjlan} 2.${gl_bai} Sing-box      ${gl_lv}[运行中]${gl_bai}"; else echo -e "${gl_kjlan} 2.${gl_bai} Sing-box      ${gl_hui}[未运行]${gl_bai}"; fi
        echo -e "------------------------------------------------"
        echo -e "${gl_hui} 0. 返回主菜单${gl_bai}"
        echo -e "------------------------------------------------"
        read -p "选项: " c
        case "$c" in
            1) xray_management ;;
            2) singbox_management ;;
            0) return ;;
        esac
    done
}

# ===== 模块: 系统辅助 (完整版 v1.6) =====
linux_info() {
    clear
    echo -e "${gl_huang}正在采集系统信息...${gl_bai}"
    ip_address

    local cpu_info=$(lscpu | awk -F': +' '/Model name:/ {print $2; exit}')
    local cpu_usage_percent=$(awk '{u=$2+$4; t=$2+$4+$5; if (NR==1){u1=u; t1=t;} else printf "%.0f\n", (($2+$4-u1) * 100 / (t-t1))}' \
        <(grep 'cpu ' /proc/stat) <(sleep 1; grep 'cpu ' /proc/stat))
    local cpu_cores=$(nproc)
    local cpu_freq=$(cat /proc/cpuinfo | grep "MHz" | head -n 1 | awk '{printf "%.1f GHz\n", $4/1000}')
    local mem_info=$(free -b | awk 'NR==2{printf "%.2f/%.2fM (%.2f%%)", $3/1024/1024, $2/1024/1024, $3*100/$2}')
    local disk_info=$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}')
    
    # 仅保留纯粹的信息获取
    local ipinfo=$(curl -s ipinfo.io)
    local country=$(echo "$ipinfo" | grep 'country' | awk -F': ' '{print $2}' | tr -d '",')
    local city=$(echo "$ipinfo" | grep 'city' | awk -F': ' '{print $2}' | tr -d '",')
    local isp_info=$(echo "$ipinfo" | grep 'org' | awk -F': ' '{print $2}' | tr -d '",')
    
    local load=$(uptime | awk '{print $(NF-2), $(NF-1), $NF}')
    local dns_addresses=$(awk '/^nameserver/{printf "%s ", $2} END {print ""}' /etc/resolv.conf)
    local cpu_arch=$(uname -m)
    local hostname=$(uname -n)
    local kernel_version=$(uname -r)
    local congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
    local queue_algorithm=$(sysctl -n net.core.default_qdisc)
    local os_info=$(grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | tr -d '"')
    
    # 调用统计
    output_status
    
    local current_time=$(date "+%Y-%m-%d %I:%M %p")
    local swap_info=$(free -m | awk 'NR==3{used=$3; total=$2; if (total == 0) {percentage=0} else {percentage=used*100/total}; printf "%dM/%dM (%d%%)", used, total, percentage}')
    local runtime=$(cat /proc/uptime | awk -F. '{run_days=int($1 / 86400);run_hours=int(($1 % 86400) / 3600);run_minutes=int(($1 % 3600) / 60); if (run_days > 0) printf("%d天 ", run_days); if (run_hours > 0) printf("%d时 ", run_hours); printf("%d分\n", run_minutes)}')
    local timezone=$(current_timezone)
    local tcp_count=$(ss -t | wc -l)
    local udp_count=$(ss -u | wc -l)

    echo ""
    echo -e "${gl_lv}系统信息概览${gl_bai}"
    echo -e "${gl_kjlan}-------------"
    echo -e "${gl_kjlan}主机名:         ${gl_bai}$hostname ($country_code $flag)"
    echo -e "${gl_kjlan}系统版本:       ${gl_bai}$os_info"
    echo -e "${gl_kjlan}Linux版本:      ${gl_bai}$kernel_version"
    echo -e "${gl_kjlan}-------------"
    echo -e "${gl_kjlan}CPU架构:        ${gl_bai}$cpu_arch"
    echo -e "${gl_kjlan}CPU型号:        ${gl_bai}$cpu_info"
    echo -e "${gl_kjlan}CPU核心数:      ${gl_bai}$cpu_cores"
    echo -e "${gl_kjlan}CPU频率:        ${gl_bai}$cpu_freq"
    echo -e "${gl_kjlan}-------------"
    echo -e "${gl_kjlan}CPU占用:        ${gl_bai}$cpu_usage_percent%"
    echo -e "${gl_kjlan}系统负载:       ${gl_bai}$load"
    echo -e "${gl_kjlan}TCP|UDP连接数:  ${gl_bai}$tcp_count|$udp_count"
    echo -e "${gl_kjlan}物理内存:       ${gl_bai}$mem_info"
    echo -e "${gl_kjlan}虚拟内存:       ${gl_bai}$swap_info"
    echo -e "${gl_kjlan}硬盘占用:       ${gl_bai}$disk_info"
    echo -e "${gl_kjlan}-------------"
    echo -e "${gl_kjlan}总接收:         ${gl_bai}$rx"
    echo -e "${gl_kjlan}总发送:         ${gl_bai}$tx"
    echo -e "${gl_kjlan}-------------"
    echo -e "${gl_kjlan}网络算法:       ${gl_bai}$congestion_algorithm $queue_algorithm"
    echo -e "${gl_kjlan}-------------"
    echo -e "${gl_kjlan}运营商:         ${gl_bai}$isp_info"
    if [ -n "$ipv4_address" ]; then
        echo -e "${gl_kjlan}IPv4地址:       ${gl_bai}$ipv4_address"
    fi
    if [ -n "$ipv6_address" ]; then
        echo -e "${gl_kjlan}IPv6地址:       ${gl_bai}$ipv6_address"
    fi
    echo -e "${gl_kjlan}DNS地址:        ${gl_bai}$dns_addresses"
    echo -e "${gl_kjlan}地理位置:       ${gl_bai}$country $city"
    echo -e "${gl_kjlan}系统时间:       ${gl_bai}$timezone $current_time"
    echo -e "${gl_kjlan}-------------"
    echo -e "${gl_kjlan}运行时长:       ${gl_bai}$runtime"
    echo
    echo "按回车返回..."
    read -r
}

linux_update() {
    echo -e "${gl_huang}正在更新...${gl_bai}"
    apt update && apt full-upgrade -y
    [ -f /var/run/reboot-required ] && echo -e "${gl_hong}内核已更新，建议重启${gl_bai}" || echo -e "${gl_lv}更新完成${gl_bai}"
    read -p "..."
}

linux_clean() {
    echo -e "${gl_huang}清理垃圾...${gl_bai}"
    apt autoremove --purge -y; apt clean; journalctl --vacuum-time=1s
    echo -e "${gl_lv}完成${gl_bai}"; read -p "..."
}

update_script() {
    echo -e "${gl_huang}更新脚本...${gl_bai}"
    curl -sS -o /usr/local/bin/x "https://raw.githubusercontent.com/OPPO518/sh/main/x.sh" && chmod +x /usr/local/bin/x && exec /usr/local/bin/x
}

# ===== 主菜单 (完整版) =====
main_menu() {
    while true; do
        clear
        echo -e "${gl_kjlan}Debian VPS 运维工具箱 v2.0 (Ultimate)${gl_bai}"
        echo "------------------------------------------------"
        echo -e " 1. 系统初始化 (System Init)"
        echo -e " 2. Swap 管理"
        echo "------------------------------------------------"
        echo -e " 3. 防火墙 (Nftables)"
        echo -e " 4. 防暴破 (Fail2ban)"
        echo -e " 8. 核心代理 (Xray / Sing-box) ${gl_hong}[Reality]${gl_bai}"
        echo "------------------------------------------------"
        echo -e " 5. 系统信息 (Info)"
        echo -e " 6. 系统更新 (Update)"
        echo -e " 7. 系统清理 (Clean)"
        echo "------------------------------------------------"
        echo -e " 9. 更新脚本 (Update Script)"
        echo -e " 0. 退出 (Exit)"
        echo "------------------------------------------------"
        read -p "选项: " c
        case "$c" in
            1) system_initialize ;;
            2) swap_management ;;
            3) nftables_management ;;
            4) fail2ban_management ;;
            8) proxy_menu ;;
            5) linux_info ;;
            6) linux_update ;;
            7) linux_clean ;;
            9) update_script ;;
            0) exit 0 ;;
            *) echo "无效选项"; sleep 1 ;;
        esac
    done
}

[ "$(id -u)" != "0" ] && { echo "请使用 root 运行"; exit 1; }
main_menu
