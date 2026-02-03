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
gl_kjlan='\033[96m'
gl_hui='\e[37m'

# ===== 辅助函数: 获取国旗 Emoji =====
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

# ===== 辅助函数: 系统信息收集 =====
ip_address() {
    public_ip=$(curl -s --max-time 3 https://ipinfo.io/ip)
    [ -z "$public_ip" ] && public_ip=$(hostname -I | awk '{print $1}')
    country_code=$(curl -s --max-time 3 https://ipinfo.io/country | tr -d '\n')
    flag=$(get_flag_local "$country_code")
}

output_status() {
    output=$(awk 'BEGIN { rx_total = 0; tx_total = 0 }
        $1 ~ /^(eth|ens|enp|eno)[0-9]+/ { rx_total += $2; tx_total += $10 }
        END {
            rx_units = "B"; tx_units = "B";
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

# ===== 模块 1: 系统初始化 =====
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
    
    # 换源
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

    # 内核参数配置
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
        # 落地机策略
        echo "net.ipv4.ip_forward=0" >> /etc/sysctl.d/99-vps-optimize.conf
        echo "net.ipv6.conf.all.forwarding=0" >> /etc/sysctl.d/99-vps-optimize.conf
    else
        # 中转机策略
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
        read -p "系统内核已更新，是否重启? (y/n): " rb
        [[ "$rb" =~ ^[yY]$ ]] && reboot
    else
        read -p "按回车返回..."
    fi
}

# ===== 模块 2: Swap 管理 =====
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
            1) read -p "输入大小(MB): " s; 
               if [[ "$s" =~ ^[0-9]+$ ]]; then
                   swapoff -a 2>/dev/null; rm -f /swapfile; dd if=/dev/zero of=/swapfile bs=1M count=$s status=progress; 
                   chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile; 
                   sed -i '/swapfile/d' /etc/fstab; echo '/swapfile none swap sw 0 0' >> /etc/fstab; 
                   echo "成功"; read -p "..."
               fi ;;
            2) swapoff -a; rm -f /swapfile; sed -i '/swapfile/d' /etc/fstab; echo "已删除"; read -p "..." ;;
            0) return ;;
        esac
    done
}

# ===== 模块 3: Nftables 防火墙 =====
nftables_management() {
    detect_ssh() { ss -tlnp | grep 'sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -n 1 || echo 22; }
    
    init_fw() {
        local type=$1; local port=$(detect_ssh)
        echo -e "${gl_huang}清理环境...${gl_bai}"
        ufw disable 2>/dev/null; apt purge ufw -y 2>/dev/null
        
        # 强制同步内核参数
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
            1) init_fw landing ;;
            2) init_fw transit ;;
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

# ===== 模块 4: Fail2ban =====
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
            2) echo "按回车退出..."; tail -f -n 20 /var/log/fail2ban.log & pid=$!; read -r; kill $pid ;;
            3) read -p "IP: " ip; fail2ban-client set sshd unbanip $ip; fail2ban-client set recidive unbanip $ip; echo "OK"; sleep 1 ;;
            4) apt purge fail2ban -y; rm -rf /etc/fail2ban; nft delete table inet f2b-table 2>/dev/null; echo "已卸载"; read -p "..." ;;
            0) return ;;
        esac
    done
}

# ===== 模块 8A: Xray 核心管理 =====
xray_management() {
    BIN_PATH="/usr/local/bin/xray"
    CONF_DIR="/usr/local/etc/xray"
    INFO_FILE="${CONF_DIR}/info.txt"

    ensure_port_open() {
        if command -v nft &>/dev/null; then
            if nft list tables | grep -q "my_landing"; then t="my_landing"; s="allowed_tcp"; su="allowed_udp";
            elif nft list tables | grep -q "my_transit"; then t="my_transit"; s="local_tcp"; su="local_udp"; else return; fi
            if ! nft list set inet $t $s 2>/dev/null | grep -q "$1"; then
                echo -e "${gl_huang}自动放行端口 $1...${gl_bai}"
                nft add element inet $t $s { $1 }; nft add element inet $t $su { $1 }
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
        ip=$(curl -s --max-time 3 https://ipinfo.io/ip)
        code=$(curl -s --max-time 3 https://ipinfo.io/country | tr -d '\n')
        flag=$(get_flag_local "$code")
        link="vless://$uuid@$ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=$pub&sid=$sid&type=tcp&headerType=none#${flag}Xray-Reality"

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
        if [ -f "$INFO_FILE" ]; then clear; cat $INFO_FILE; else echo "未找到配置"; fi
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
        if systemctl is-active --quiet xray; then v=$($BIN_PATH version 2>/dev/null | head -n 1 | awk '{print $2}'); echo -e "状态: ${gl_lv}● 运行中 ($v)${gl_bai}"; else echo -e "状态: ${gl_hong}● 已停止${gl_bai}"; fi
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
            4) echo "回车退出..."; journalctl -u xray -n 50 -f & pid=$!; read -r; kill $pid ;;
            5) systemctl restart xray; echo "已重启"; sleep 1 ;;
            6) systemctl stop xray; echo "已停止"; sleep 1 ;;
            9) uninstall_xray ;;
            0) return ;;
        esac
    done
}

# ===== 模块 8B: Sing-box 核心管理 =====
singbox_management() {
    BIN_PATH="/usr/bin/sing-box"
    CONF_DIR="/etc/sing-box"
    INFO_FILE="${CONF_DIR}/info.txt"

    ensure_port_open() {
        if command -v nft &>/dev/null; then
            if nft list tables | grep -q "my_landing"; then t="my_landing"; s="allowed_tcp"; su="allowed_udp";
            elif nft list tables | grep -q "my_transit"; then t="my_transit"; s="local_tcp"; su="local_udp"; else return; fi
            if ! nft list set inet $t $s 2>/dev/null | grep -q "$1"; then
                echo -e "${gl_huang}自动放行端口 $1...${gl_bai}"
                nft add element inet $t $s { $1 }; nft add element inet $t $su { $1 }
                nft list ruleset > /etc/nftables.conf
            fi
        fi
    }

    get_ver() {
        tag=$(curl -sL --max-time 5 "https://api.github.com/repos/SagerNet/sing-box/releases/latest" | grep '"tag_name":' | head -n 1 | cut -d '"' -f 4)
        [ -z "$tag" ] && echo "v1.12.13" || echo "$tag"
    }

    install_sb() {
        echo -e "${gl_huang}获取最新版本...${gl_bai}"
        ver=$(get_ver); arch=$(uname -m); [ "$arch" == "x86_64" ] && sa="amd64" || sa="arm64"
        url="https://github.com/SagerNet/sing-box/releases/download/${ver}/sing-box_${ver#v}_linux_${sa}.deb"
        
        echo -e "下载: $ver"
        if curl -L -o /tmp/sb.deb "$url"; then
            if command -v sing-box &>/dev/null; then
                echo "执行安全升级..."
                ar x /tmp/sb.deb data.tar.xz --output /tmp/
                tar -xf /tmp/data.tar.xz -C /tmp/ ./usr/bin/sing-box
                systemctl stop sing-box; cp -f /tmp/usr/bin/sing-box /usr/bin/sing-box; chmod +x /usr/bin/sing-box
                systemctl restart sing-box; rm -rf /tmp/sb.deb /tmp/data.tar.xz /tmp/usr
                echo -e "${gl_lv}升级完成${gl_bai}"
            else
                echo "执行安装..."
                apt install /tmp/sb.deb -y; rm -f /tmp/sb.deb
                systemctl daemon-reload; systemctl enable sing-box; systemctl restart sing-box
                echo -e "${gl_lv}安装完成${gl_bai}"
            fi
        else
            echo "下载失败"; 
        fi
        read -p "..."
    }

    config_sb() {
        [ ! -f "$BIN_PATH" ] && { echo "未安装"; sleep 1; return; }
        port=$(shuf -i 20000-65000 -n 1)
        ensure_port_open "$port"
        echo -e "${gl_huang}生成配置...${gl_bai}"
        
        uuid=$(sing-box generate uuid)
        kp=$(sing-box generate reality-keypair)
        pri=$(echo "$kp" | grep "PrivateKey" | awk '{print $2}')
        pub=$(echo "$kp" | grep "PublicKey" | awk '{print $2}')
        sid=$(openssl rand -hex 8)
        
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
        ip=$(curl -s --max-time 3 https://ipinfo.io/ip)
        code=$(curl -s --max-time 3 https://ipinfo.io/country | tr -d '\n')
        flag=$(get_flag_local "$code")
        link="vless://$uuid@$ip:$port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=$pub&sid=$sid&type=tcp&headerType=none#${flag}SingBox-Reality"

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
        [ -f "$INFO_FILE" ] && { clear; cat $INFO_FILE; } || echo "未找到配置"
        [ "${FUNCNAME[1]}" != "config_sb" ] && read -p "..."
    }

    uninstall_sb() {
        echo "正在卸载..."
        systemctl stop sing-box; apt purge sing-box -y; apt autoremove -y; rm -rf $CONF_DIR /usr/bin/sing-box
        echo "完成"; read -p "..."
    }

    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#           Sing-box 核心管理 (Reality)        #"
        echo -e "################################################${gl_bai}"
        if systemctl is-active --quiet sing-box; then v=$($BIN_PATH version | head -n 1 | awk '{print $3}'); echo -e "状态: ${gl_lv}● 运行中 ($v)${gl_bai}"; else echo -e "状态: ${gl_hong}● 已停止${gl_bai}"; fi
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
            4) echo "回车退出..."; journalctl -u sing-box -n 50 -f & pid=$!; read -r; kill $pid ;;
            5) systemctl restart sing-box; echo "已重启"; sleep 1 ;;
            6) systemctl stop sing-box; echo "已停止"; sleep 1 ;;
            9) uninstall_sb ;;
            0) return ;;
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

# ===== 模块: 系统辅助 (完整版) =====
linux_info() {
    clear
    echo "采集信息中..."
    ip_address
    output_status
    local cpu=$(lscpu | grep 'Model name' | cut -f2 -d: | sed 's/^[ \t]*//')
    local mem=$(free -m | awk 'NR==2{printf "%d/%dMB (%.2f%%)", $3, $2, $3*100/$2}')
    local disk=$(df -h / | awk 'NR==2{print $3 "/" $2 " (" $5 ")"}')
    echo -e "${gl_lv}系统信息${gl_bai}"
    echo "------------------------------------------------"
    echo -e "主机: $(hostname) ($country_code $flag)"
    echo -e "系统: $(cat /etc/issue | tr -d '\\n\\l')"
    echo -e "CPU:  $cpu ($(nproc)核)"
    echo -e "内存: $mem"
    echo -e "硬盘: $disk"
    echo -e "流量: $rx / $tx"
    echo -e "时间: $(date) ($(current_timezone))"
    read -p "..."
}

linux_update() {
    echo "正在更新..."
    apt update && apt full-upgrade -y
    [ -f /var/run/reboot-required ] && echo "内核已更新，建议重启" || echo "更新完成"
    read -p "..."
}

linux_clean() {
    echo "清理垃圾..."
    apt autoremove --purge -y; apt clean; journalctl --vacuum-time=1s
    echo "完成"; read -p "..."
}

update_script() {
    echo "更新脚本..."
    # 请务必修改为你自己的 GitHub 地址！
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
