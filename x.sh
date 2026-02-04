#!/bin/bash

# =========================================================
#  Debian VPS 运维工具箱 (v2.2 Full Restore Edition)
#  集成: Init, Swap, Nftables, Fail2ban, Xray, Sing-box
# =========================================================

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

# ===== 全局辅助: 获取国旗 Emoji =====
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
    
    if echo "$isp_info" | grep -Eiq 'mobile|unicom|telecom'; then 
        ipv4_address=$(get_local_ip)
    else 
        ipv4_address="$public_ip"
    fi
    ipv6_address=$(curl -s --max-time 1 https://v6.ipinfo.io/ip && echo)
    country_code=$(curl -s --max-time 3 https://ipinfo.io/country | tr -d '\n')
    flag=$(get_flag_local "$country_code")
}

# ===== 辅助函数: 网络流量统计 =====
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

# ===== 辅助函数: 时区检测 =====
current_timezone() {
    if grep -q 'Alpine' /etc/issue; then 
        date +"%Z %z"
    else 
        timedatectl | grep "Time zone" | awk '{print $3}'
    fi
}

# ===== 模块 1: 系统初始化 (还原 1.6 详细风格) =====
system_initialize() {
    clear
    echo -e "${gl_kjlan}################################################"
    echo -e "#            系统初始化配置 (System Init)        #"
    echo -e "################################################${gl_bai}"
    
    local os_ver=""
    if grep -q "bullseye" /etc/os-release; then 
        os_ver="11"
        echo -e "当前系统: ${gl_huang}Debian 11 (Bullseye)${gl_bai}"
    elif grep -q "bookworm" /etc/os-release; then 
        os_ver="12"
        echo -e "当前系统: ${gl_huang}Debian 12 (Bookworm)${gl_bai}"
    else 
        echo -e "${gl_hong}错误: 本脚本仅支持 Debian 11 或 12 系统！${gl_bai}"
        read -p "按回车返回..."
        return
    fi
    
    echo -e "${gl_hui}* 包含换源、BBR、时区及落地/中转环境配置${gl_bai}"
    echo -e "------------------------------------------------"
    echo -e "请设定当前 VPS 的业务角色："
    echo -e "${gl_lv} 1.${gl_bai} 落地机 (Landing)  -> [关闭转发 | 极简安全]"
    echo -e "${gl_lv} 2.${gl_bai} 中转机 (Transit)  -> [开启转发 | 路由优化]"
    echo -e "${gl_hui} 0. 返回主菜单${gl_bai}"
    echo -e "------------------------------------------------"
    read -p "请输入选项 [0-2]: " role_choice
    
    # 增加有效性校验
    case "$role_choice" in
        1|2) ;;
        0) return ;;
        *) echo -e "${gl_hong}无效选项，操作已取消！${gl_bai}"; sleep 1; return ;;
    esac

    echo -e "${gl_kjlan}>>> 正在执行初始化...${gl_bai}"
    
    # 备份与换源
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

    # 更新与安装工具
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
        echo "net.ipv4.ip_forward=0" >> /etc/sysctl.d/99-vps-optimize.conf
        echo "net.ipv6.conf.all.forwarding=0" >> /etc/sysctl.d/99-vps-optimize.conf
    else
        modprobe nft_nat 2>/dev/null; modprobe br_netfilter 2>/dev/null
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.d/99-vps-optimize.conf
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-vps-optimize.conf
        echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.d/99-vps-optimize.conf
    fi
    sysctl --system
    
    # 时区设置
    timedatectl set-timezone Asia/Shanghai
    systemctl enable --now systemd-timesyncd
    
    # 初始化报告
    echo -e ""
    echo -e "${gl_lv}====== 初始化配置报告 (Init Report) ======${gl_bai}"
    local bbr_status=$(sysctl -n net.ipv4.tcp_congestion_control)
    echo -e " 1. BBR 算法: \t${gl_kjlan}${bbr_status}${gl_bai}"
    local fw_status=$(sysctl -n net.ipv4.ip_forward)
    if [ "$fw_status" == "1" ]; then
        echo -e " 2. 内核转发: \t${gl_huang}已开启 (中转模式)${gl_bai}"
    else
        echo -e " 2. 内核转发: \t${gl_lv}已关闭 (落地模式)${gl_bai}"
    fi
    local current_time=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e " 3. 当前时间: \t${gl_bai}${current_time} (CST)${gl_bai}"
    echo -e "------------------------------------------------"
    
    if [ -f /var/run/reboot-required ]; then
        echo -e "${gl_hong}!!! 检测到内核更新，必须重启 !!!${gl_bai}"
        read -p "是否立即重启? (y/n): " rb
        [[ "$rb" =~ ^[yY]$ ]] && reboot
    else
        read -p "按回车返回..."
    fi
}

# ===== 模块 2: Swap 管理 (还原 1.6 风格) =====
swap_management() {
    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#            Swap 虚拟内存管理                     #"
        echo -e "################################################${gl_bai}"
        
        local swap_total=$(free -m | grep Swap | awk '{print $2}')
        local swap_used=$(free -m | grep Swap | awk '{print $3}')
        
        if [ "$swap_total" -eq 0 ]; then
             echo -e "当前状态: ${gl_hong}未启用 Swap${gl_bai}"
        else
             echo -e "当前状态: ${gl_lv}已启用${gl_bai} | 总计: ${gl_kjlan}${swap_total}MB${gl_bai} | 已用: ${gl_huang}${swap_used}MB${gl_bai}"
        fi
        
        echo -e "------------------------------------------------"
        echo -e "${gl_lv} 1.${gl_bai} 设置/扩容 Swap (建议内存的 1-2 倍)"
        echo -e "${gl_hong} 2.${gl_bai} 卸载/关闭 Swap"
        echo -e "${gl_hui} 0. 返回上级菜单${gl_bai}"
        echo -e "------------------------------------------------"
        
        read -p "请输入选项 [0-2]: " choice
        case "$choice" in
            1)
                echo -e "------------------------------------------------"
                read -p "请输入需要添加的 Swap 大小 (单位: MB，例如 1024): " swap_size
                if [[ ! "$swap_size" =~ ^[0-9]+$ ]]; then
                    echo -e "${gl_hong}错误: 请输入纯数字！${gl_bai}"; sleep 1; continue
                fi

                echo -e "${gl_huang}正在处理 (清理旧文件 -> 创建新文件)...${gl_bai}"
                swapoff -a 2>/dev/null
                rm -f /swapfile 2>/dev/null
                sed -i '/swapfile/d' /etc/fstab

                if dd if=/dev/zero of=/swapfile bs=1M count=$swap_size status=progress; then
                    chmod 600 /swapfile
                    mkswap /swapfile
                    swapon /swapfile
                    echo '/swapfile none swap sw 0 0' >> /etc/fstab
                    echo -e "${gl_lv}成功！Swap 已设定为 ${swap_size}MB。${gl_bai}"
                else
                    echo -e "${gl_hong}创建失败，请检查磁盘空间。${gl_bai}"
                fi
                read -p "按回车键继续..."
                ;;
            2)
                echo -e "${gl_huang}正在卸载 Swap...${gl_bai}"
                swapoff -a
                rm -f /swapfile
                sed -i '/swapfile/d' /etc/fstab
                echo -e "${gl_lv}Swap 已移除。${gl_bai}"
                read -p "按回车键继续..."
                ;;
            0) return ;;
            *) echo -e "${gl_hong}无效选项${gl_bai}"; sleep 1 ;;
        esac
    done
}

# ===== 模块 3: Nftables 防火墙 (还原 1.6 + 修复显示) =====
nftables_management() {
    # 自动检测 SSH 端口
    detect_ssh_port() {
        local port=$(ss -tlnp | grep 'sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -n 1)
        if [ -z "$port" ]; then port="22"; fi
        echo "$port"
    }

    # 落地机初始化
    init_landing_firewall() {
        local ssh_port=$(detect_ssh_port)
        echo -e "${gl_huang}检测到 SSH 端口: ${ssh_port} (将强制放行)${gl_bai}"
        echo -e "${gl_kjlan}正在部署 落地机(Landing) 策略...${gl_bai}"
        
        echo -e "正在清理冲突组件..."
        ufw disable 2>/dev/null || true
        apt purge ufw -y 2>/dev/null
        
        sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1
        rm -f /etc/sysctl.d/99-transit-forward.conf
        
        apt update -y && apt install nftables -y
        systemctl enable nftables

        cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f
flush ruleset
table inet my_landing {
    set allowed_tcp { type inet_service; flags interval; }
    set allowed_udp { type inet_service; flags interval; }
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        icmp type echo-request accept
        icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
        tcp dport $ssh_port accept
        tcp dport @allowed_tcp accept
        udp dport @allowed_udp accept
    }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain output { type filter hook output priority 0; policy accept; }
}
EOF
        nft -f /etc/nftables.conf
        systemctl restart nftables
        echo -e "${gl_lv}落地机防火墙部署完成！${gl_bai}"
    }

    # 中转机初始化
    init_transit_firewall() {
        local ssh_port=$(detect_ssh_port)
        echo -e "${gl_huang}检测到 SSH 端口: ${ssh_port} (将强制放行)${gl_bai}"
        echo -e "${gl_kjlan}正在部署 中转机(Transit) 策略...${gl_bai}"

        ufw disable 2>/dev/null || true
        apt purge ufw -y 2>/dev/null
        apt update -y && apt install nftables -y
        systemctl enable nftables

        modprobe nft_nat 2>/dev/null
        modprobe br_netfilter 2>/dev/null
        
        # 强制开启转发
        sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
        echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-transit-forward.conf
        
        cat > /etc/nftables.conf << EOF
#!/usr/sbin/nft -f
flush ruleset
table inet my_transit {
    set local_tcp { type inet_service; flags interval; }
    set local_udp { type inet_service; flags interval; }
    map fwd_tcp { type inet_service : ipv4_addr . inet_service; }
    map fwd_udp { type inet_service : ipv4_addr . inet_service; }
    chain input {
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
        icmp type echo-request accept
        icmpv6 type { echo-request, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept
        tcp dport $ssh_port accept
        tcp dport @local_tcp accept
        udp dport @local_udp accept
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
        ct state established,related accept
        tcp flags syn tcp option maxseg size set 1360
    }
    chain prerouting {
        type nat hook prerouting priority -100; policy accept;
        dnat ip to tcp dport map @fwd_tcp
        dnat ip to udp dport map @fwd_udp
    }
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        oifname != "lo" masquerade
    }
}
EOF
        nft -f /etc/nftables.conf
        systemctl restart nftables
        echo -e "${gl_lv}中转机防火墙部署完成！${gl_bai}"
    }

    # 可视化列表 (修正版: 使用 awk 循环查找冒号)
    list_rules_ui() {
        echo -e "${gl_huang}=== 防火墙规则概览 (Firewall Status) ===${gl_bai}"
        
        local current_ssh=$(detect_ssh_port)
        echo -e "基础防自锁: ${gl_lv}SSH Port ${current_ssh} [✔ Accepted]${gl_bai}"
        
        local table_name=""
        local set_tcp_name=""
        local set_udp_name=""
        
        if nft list tables | grep -q "my_transit"; then 
            table_name="my_transit"; set_tcp_name="local_tcp"; set_udp_name="local_udp"
        elif nft list tables | grep -q "my_landing"; then
            table_name="my_landing"; set_tcp_name="allowed_tcp"; set_udp_name="allowed_udp"
        else 
            echo -e "${gl_hong}防火墙未初始化${gl_bai}"; return
        fi

        echo "------------------------------------------------"
        echo -e "${gl_huang}=== 自定义端口放行 ===${gl_bai}"
        # 使用 awk 提取集合元素，忽略缩进
        local tcp_list=$(nft list set inet $table_name $set_tcp_name 2>/dev/null | grep 'elements =' | awk -F '{' '{print $2}' | awk -F '}' '{print $1}' | tr -d ' ')
        local udp_list=$(nft list set inet $table_name $set_udp_name 2>/dev/null | grep 'elements =' | awk -F '{' '{print $2}' | awk -F '}' '{print $1}' | tr -d ' ')

        echo -e "[TCP] ${gl_kjlan}${tcp_list:-无}${gl_bai}"
        echo -e "[UDP] ${gl_kjlan}${udp_list:-无}${gl_bai}"
        echo "------------------------------------------------"
        
        if [ "$table_name" == "my_transit" ]; then
            echo -e "${gl_kjlan}=== 端口转发规则 ===${gl_bai}"
            echo "--- TCP 转发 ---"
            # 核心修复: 循环查找冒号
            nft list map inet my_transit fwd_tcp 2>/dev/null | grep -v 'type' | tr -d '{},=' | awk '{for(i=1;i<=NF;i++) if($i==":") printf "TCP %-6s -> %s : %s\n", $(i-1), $(i+1), $(i+3)}'
            
            echo "--- UDP 转发 ---"
            nft list map inet my_transit fwd_udp 2>/dev/null | grep -v 'type' | tr -d '{},=' | awk '{for(i=1;i<=NF;i++) if($i==":") printf "UDP %-6s -> %s : %s\n", $(i-1), $(i+1), $(i+3)}'
            echo "------------------------------------------------"
        fi
    }

    # Nftables 菜单循环
    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#          Nftables 防火墙与中转管理           #"
        echo -e "################################################${gl_bai}"
        
        local ssh_p=$(detect_ssh_port)
        echo -e "当前 SSH 端口: ${gl_lv}${ssh_p}${gl_bai} (自动保护中)"
        
        local mode="none"
        local table=""
        local set_tcp=""
        local set_udp=""
        
        if nft list tables | grep -q "my_transit"; then
            echo -e "当前模式: ${gl_kjlan}中转机 (Transit NAT)${gl_bai}"
            mode="transit"
            set_tcp="local_tcp"; set_udp="local_udp"
            table="my_transit"
        elif nft list tables | grep -q "my_landing"; then
            echo -e "当前模式: ${gl_huang}落地机 (Landing FW)${gl_bai}"
            mode="landing"
            set_tcp="allowed_tcp"; set_udp="allowed_udp"
            table="my_landing"
        else
            echo -e "当前模式: ${gl_hong}未初始化 / 未知${gl_bai}"
            mode="none"
        fi
        echo -e "------------------------------------------------"
        
        if [ "$mode" == "none" ]; then
            echo -e "${gl_lv} 1.${gl_bai} 初始化为：落地机防火墙 (仅放行)"
            echo -e "${gl_lv} 2.${gl_bai} 初始化为：中转机防火墙 (含转发面板)"
        else
            echo -e "${gl_lv} 3.${gl_bai} 查看所有规则 (List Rules)"
            echo -e "${gl_lv} 4.${gl_bai} 添加放行端口 (Allow Port)"
            echo -e "${gl_lv} 5.${gl_bai} 删除放行端口 (Delete Port)"
            if [ "$mode" == "transit" ]; then
                echo -e "${gl_kjlan} 6.${gl_bai} 添加转发规则 (Add Forward)"
                echo -e "${gl_kjlan} 7.${gl_bai} 删除转发规则 (Del Forward)"
            fi
            echo -e "${gl_hong} 8.${gl_bai} 重置/切换模式 (Re-Init)"
        fi
        
        echo -e "------------------------------------------------"
        echo -e "${gl_hui} 0. 返回主菜单${gl_bai}"
        
        read -p "请输入选项: " nf_choice

        case "$nf_choice" in
            1) 
                if [ "$mode" == "none" ]; then init_landing_firewall; else echo -e "${gl_hong}请先执行选项 8 重置！${gl_bai}"; fi
                read -p "按回车继续..." ;;
            2) 
                if [ "$mode" == "none" ]; then init_transit_firewall; else echo -e "${gl_hong}请先执行选项 8 重置！${gl_bai}"; fi
                read -p "按回车继续..." ;;
            3) list_rules_ui; read -p "按回车继续..." ;;
            4) 
                list_rules_ui
                echo -e "${gl_hui}提示: 支持单端口(8080) 或 范围(50000:60000)${gl_bai}"
                read -p "请输入要放行的端口: " p_port
                # 支持 : 和 -，并自动格式化
                if [[ "$p_port" =~ ^[0-9:-]+$ ]]; then
                    p_port=$(echo "$p_port" | tr ':' '-')
                    nft add element inet $table $set_tcp { $p_port }
                    nft add element inet $table $set_udp { $p_port }
                    nft list ruleset > /etc/nftables.conf
                    echo -e "${gl_lv}端口 $p_port 已放行。${gl_bai}"
                else
                    echo -e "${gl_hong}格式错误！${gl_bai}"
                fi
                sleep 1
                ;;
            5)
                list_rules_ui
                read -p "请输入要删除的端口: " p_port
                if [[ "$p_port" =~ ^[0-9:-]+$ ]]; then
                    p_port=$(echo "$p_port" | tr ':' '-')
                    nft delete element inet $table $set_tcp { $p_port } 2>/dev/null
                    nft delete element inet $table $set_udp { $p_port } 2>/dev/null
                    nft list ruleset > /etc/nftables.conf
                    echo -e "${gl_hong}端口 $p_port 已移除。${gl_bai}"
                fi
                sleep 1
                ;;
            6) 
                if [ "$mode" == "transit" ]; then
                    list_rules_ui
                    echo -e "请输入转发规则:"
                    read -p "1. 本机监听端口 (如 8080): " lp
                    read -p "2. 目标 IP 地址 (如 1.1.1.1): " dip
                    read -p "3. 目标端口     (如 80): " dp
                    
                    if [[ -n "$lp" && -n "$dip" && -n "$dp" ]]; then
                        nft add element inet my_transit fwd_tcp { $lp : $dip . $dp }
                        nft add element inet my_transit fwd_udp { $lp : $dip . $dp }
                        nft list ruleset > /etc/nftables.conf
                        echo -e "${gl_lv}转发规则已添加。${gl_bai}"
                    fi
                    sleep 1
                fi
                ;;
            7) 
                if [ "$mode" == "transit" ]; then
                    list_rules_ui
                    read -p "请输入要删除转发的本机端口: " lp
                    if [[ -n "$lp" ]]; then
                         nft delete element inet my_transit fwd_tcp { $lp } 2>/dev/null
                         nft delete element inet my_transit fwd_udp { $lp } 2>/dev/null
                         nft list ruleset > /etc/nftables.conf
                         echo -e "${gl_hong}转发规则已移除。${gl_bai}"
                    fi
                    sleep 1
                fi
                ;;
            8) 
                echo -e "${gl_hong}注意: 这将清空所有规则！${gl_bai}"
                read -p "确定重置吗？(y/n): " confirm
                if [[ "$confirm" == "y" ]]; then
                    echo -e "${gl_huang}正在清除...${gl_bai}"
                    nft flush ruleset
                    echo "#!/usr/sbin/nft -f" > /etc/nftables.conf
                    echo "flush ruleset" >> /etc/nftables.conf
                    if systemctl is-active --quiet fail2ban; then 
                        echo -e "${gl_huang}重启 Fail2ban 以恢复挂载...${gl_bai}"
                        systemctl restart fail2ban
                    fi
                    mode="none"
                    echo -e "${gl_lv}已重置。${gl_bai}"
                    sleep 1
                fi
                ;;
            0) return ;;
            *) echo "无效选项" ;;
        esac
    done
}

# ===== 模块 4: Fail2ban (v1.6 还原版 + 日志修复) =====
fail2ban_management() {
    detect_ssh_port() {
        local port=$(ss -tlnp | grep 'sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -n 1)
        if [ -z "$port" ]; then port="22"; fi
        echo "$port"
    }

    install_fail2ban() {
        local ssh_port=$(detect_ssh_port)
        echo -e "${gl_huang}=== Fail2ban 安装向导 ===${gl_bai}"
        echo -e "当前 SSH 端口: ${gl_lv}${ssh_port}${gl_bai}"
        
        echo -e "------------------------------------------------"
        echo -e "${gl_huang}请输入白名单 IP (防止误封自己/中转机)${gl_bai}"
        read -p "留空则跳过: " whitelist_ips
        
        local ignore_ip_conf="127.0.0.1/8 ::1"
        if [ -n "$whitelist_ips" ]; then ignore_ip_conf="$ignore_ip_conf $whitelist_ips"; fi

        echo -e "${gl_kjlan}正在安装并配置 Fail2ban...${gl_bai}"
        apt update && apt install fail2ban rsyslog -y
        systemctl enable --now rsyslog
        touch /var/log/auth.log /var/log/fail2ban.log

        cat > /etc/fail2ban/jail.d/00-default-nftables.conf << EOF
[DEFAULT]
banaction = nftables-multiport
banaction_allports = nftables-allports
chain = input
EOF
        cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
ignoreip = $ignore_ip_conf
findtime = 600
maxretry = 5
backend = polling

# [SSH-Normal] 初犯：封 3 小时
[sshd]
enabled = true
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
bantime = 10800

# [Recidive] 惯犯：阶梯式封禁 (最高 1 年)
[recidive]
enabled = true
logpath = /var/log/fail2ban.log
filter = recidive
findtime = 172800
maxretry = 2
bantime = 259200
bantime.increment = true
bantime.factor = 121.6
bantime.maxsize = 31536000
EOF
        systemctl stop fail2ban >/dev/null 2>&1
        rm -f /var/run/fail2ban/fail2ban.sock
        systemctl daemon-reload
        systemctl restart fail2ban
        systemctl enable fail2ban

        echo -e "${gl_lv}Fail2ban 部署完成！${gl_bai}"
        echo -e "已启用保护: SSH端口 $ssh_port | 白名单: ${whitelist_ips:-无}"
        sleep 2
    }

    check_f2b_status() {
        if ! systemctl is-active --quiet fail2ban; then
            echo -e "${gl_hong}Fail2ban 未运行！${gl_bai}"; return
        fi
        echo -e "${gl_huang}=== 当前封禁统计 ===${gl_bai}"
        fail2ban-client status sshd
        echo -e "------------------------------------------------"
        fail2ban-client status recidive
    }

    unban_ip() {
        read -p "请输入要解封的 IP: " target_ip
        if [ -n "$target_ip" ]; then
            fail2ban-client set sshd unbanip $target_ip
            fail2ban-client set recidive unbanip $target_ip
            echo -e "${gl_lv}尝试解封指令已发送。${gl_bai}"
        fi
    }

    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#             Fail2ban 防暴力破解管理          #"
        echo -e "################################################${gl_bai}"
        
        if systemctl is-active --quiet fail2ban; then
            echo -e "当前状态: ${gl_lv}运行中 (Running)${gl_bai}"
        else
            echo -e "当前状态: ${gl_hong}未运行 / 未安装${gl_bai}"
        fi
        
        echo -e "------------------------------------------------"
        echo -e "${gl_lv} 1.${gl_bai} 安装/重置 Fail2ban (Install/Reset)"
        echo -e "${gl_lv} 2.${gl_bai} 查看封禁状态 (Status)"
        echo -e "${gl_lv} 3.${gl_bai} 手动解封 IP (Unban IP)"
        echo -e "${gl_lv} 4.${gl_bai} 查看攻击日志 (View Log)"
        echo -e "${gl_hong} 5.${gl_bai} 卸载 Fail2ban (Uninstall)"
        echo -e "------------------------------------------------"
        echo -e "${gl_hui} 0. 返回主菜单${gl_bai}"
        
        read -p "请输入选项: " f2b_choice

        case "$f2b_choice" in
            1) install_fail2ban; read -p "按回车继续..." ;;
            2) check_f2b_status; read -p "按回车继续..." ;;
            3) unban_ip; read -p "按回车继续..." ;;
            4) 
                echo -e "${gl_huang}正在实时显示日志 (显示最后 20 行)...${gl_bai}"
                echo -e "${gl_lv}>>> 请按【回车键】停止查看并返回菜单 <<<${gl_bai}"
                echo -e "------------------------------------------------"
                tail -f -n 20 /var/log/fail2ban.log &
                local tail_pid=$!
                read -r
                kill $tail_pid >/dev/null 2>&1
                wait $tail_pid 2>/dev/null
                echo -e "${gl_lv}已停止监控。${gl_bai}"
                sleep 1
                ;;
            5)
                echo -e "${gl_huang}正在卸载...${gl_bai}"
                systemctl stop fail2ban
                systemctl disable fail2ban
                apt purge fail2ban -y
                rm -rf /etc/fail2ban /var/log/fail2ban.log
                # 清理残留的 Nftables 表
                nft delete table inet f2b-table 2>/dev/null
                echo -e "${gl_lv}卸载完成。${gl_bai}"
                read -p "按回车继续..."
                ;;
            0) return ;;
            *) echo "无效选项" ;;
        esac
    done
}

# ===== 模块 8A: Xray 核心管理 (官方直连) =====
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
        echo -e "${gl_huang}正在调用官方脚本安装 (User=root)...${gl_bai}"
        bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u root
        if [ $? -eq 0 ]; then
            echo -e "${gl_lv}安装/升级成功！${gl_bai}"
            $BIN_PATH version | head -n 1
            echo -e "------------------------------------------------"
            echo -e "请继续执行 [2. 初始化配置] 以启用服务。"
            echo -e "------------------------------------------------"
        else
            echo -e "${gl_hong}安装失败！${gl_bai}"
            echo -e "可能是网络连接 GitHub 失败，请检查 VPS 网络。"
        fi
        read -p "按回车继续..."
    }

    configure_reality() {
        if [ ! -f "$BIN_PATH" ]; then echo -e "${gl_hong}请先安装 Xray!${gl_bai}"; sleep 1; return; fi
        
        local port=$(shuf -i 20000-65000 -n 1)
        ensure_port_open "$port"
        echo -e "${gl_huang}正在生成配置...${gl_bai}"
        
        local uuid=$($BIN_PATH uuid)
        local kp=$($BIN_PATH x25519)
        local pri=$(echo "$kp" | grep -i "Private" | cut -d: -f2 | tr -d '[:space:]')
        local pub=$(echo "$kp" | grep -i "Public" | cut -d: -f2 | tr -d '[:space:]')
        [ -z "$pub" ] && pub=$(echo "$kp" | grep -i "Password" | cut -d: -f2 | tr -d '[:space:]')
        local sid=$(openssl rand -hex 8)

        if [ -z "$pub" ]; then echo -e "${gl_hong}密钥生成失败: $kp${gl_bai}"; read -p "..."; return; fi
        
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
        if [ -f "$INFO_FILE" ]; then
            clear
            cat $INFO_FILE
        else
            echo -e "${gl_hong}未找到配置信息，请先初始化！${gl_bai}"
        fi
        if [ "${FUNCNAME[1]}" != "configure_reality" ]; then 
            read -p "按回车返回..."
        fi
    }

    uninstall_xray() {
        echo -e "${gl_hong}警告: 这将删除 Xray 程序、配置及日志！${gl_bai}"
        read -p "确认卸载? (y/n): " confirm
        if [[ "$confirm" == "y" ]]; then
            echo -e "${gl_huang}正在调用官方脚本卸载...${gl_bai}"
            bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ remove --purge
            rm -rf $CONF_DIR
            echo -e "${gl_lv}Xray 已彻底卸载。${gl_bai}"
        else
            echo "已取消"
        fi
        read -p "按回车继续..."
    }

    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#         Xray 核心管理 (Official Standard)    #"
        echo -e "################################################${gl_bai}"
        if systemctl is-active --quiet xray; then
            local ver=$($BIN_PATH version 2>/dev/null | head -n 1 | awk '{print $2}')
            echo -e "状态: ${gl_lv}● 运行中${gl_bai} (Ver: ${ver:-未知})"
        else
            echo -e "状态: ${gl_hong}● 已停止 / 未安装${gl_bai}"
        fi
        
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
        read -p "请输入选项: " c
        case "$c" in
            1) install_xray ;;
            2) configure_reality ;;
            3) view_config ;;
            4) echo -e "${gl_huang}回车退出监控...${gl_bai}"; journalctl -u xray -n 50 -f & pid=$!; read -r; kill $pid; wait $pid 2>/dev/null ;;
            5) systemctl restart xray; echo -e "${gl_lv}服务已重启${gl_bai}"; sleep 1 ;;
            6) systemctl stop xray; echo -e "${gl_hong}服务已停止${gl_bai}"; sleep 1 ;;
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
            if ! nft list set inet $t $s 2>/dev/null | grep -q "$1"; then
                echo -e "${gl_huang}自动放行端口 $1...${gl_bai}"
                nft add element inet $t $s { $1 }; nft add element inet $t $su { $1 }
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
        "reality": {
          "enabled": true,
          "handshake": { "server": "www.microsoft.com", "server_port": 443 },
          "private_key": "$pri", "short_id": [ "$sid" ]
        }
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
    echo "按回车键返回..."
    read -r
}

linux_update() {
    echo -e "${gl_huang}正在进行系统更新...${gl_bai}"
    if command -v apt &>/dev/null; then
        apt update -y
        apt full-upgrade -y
        
        # 检测是否需要重启
        if [ -f /var/run/reboot-required ]; then
            echo -e "${gl_hong}注意：检测到内核或核心组件更新，需要重启才能生效！${gl_bai}"
            read -p "是否立即重启系统？(y/n): " reboot_choice
            if [[ "$reboot_choice" =~ ^[yY]$ ]]; then
                echo -e "${gl_lv}正在重启...${gl_bai}"
                reboot
            else
                echo -e "${gl_huang}已取消重启，请稍后手动重启。${gl_bai}"
            fi
        else
            echo -e "${gl_lv}系统更新完成！${gl_bai}"
        fi
    else
        echo -e "${gl_hong}错误：未检测到 apt，本脚本仅支持 Debian/Ubuntu 系统！${gl_bai}"
    fi
    read -p "按回车键返回..."
}

linux_clean() {
    echo -e "${gl_huang}正在进行系统清理...${gl_bai}"
    if command -v apt &>/dev/null; then
        apt autoremove --purge -y
        apt clean -y
        apt autoclean -y
    else
        echo -e "${gl_huang}未找到 apt，跳过包清理...${gl_bai}"
    fi
    
    # 通用清理
    if command -v journalctl &>/dev/null; then
        journalctl --rotate
        journalctl --vacuum-time=1s
        journalctl --vacuum-size=50M
    fi
    
    # 清理 /tmp 目录下超过10天未使用的文件
    find /tmp -type f -atime +10 -delete 2>/dev/null
    
    echo -e "${gl_lv}清理完成！${gl_bai}"
    read -p "按回车键返回..."
}

update_script() {
    echo -e "${gl_huang}正在检查并更新脚本...${gl_bai}"
    sh_url="https://raw.githubusercontent.com/OPPO518/sh/main/x.sh"
    if curl -sS -o /usr/local/bin/x "$sh_url"; then
        chmod +x /usr/local/bin/x
        echo -e "${gl_lv}更新成功！正在重启脚本...${gl_bai}"
        sleep 1
        exec /usr/local/bin/x
    else
        echo -e "${gl_hong}更新失败，请检查网络或 GitHub 链接！${gl_bai}"
    fi
}

# ===== 主菜单 (1.6 风格) =====
main_menu() {
    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#                                              #"
        echo -e "#           Debian VPS 极简运维工具箱          #"
        echo -e "#                                              #"
        echo -e "################################################${gl_bai}"
        echo -e "${gl_huang}当前版本: 2.2 (Final Restore)${gl_bai}"
        echo -e "------------------------------------------------"
        echo -e "${gl_lv} 1.${gl_bai} 系统初始化 (System Init) ${gl_hong}[新机必点]${gl_bai}"
        echo -e "${gl_lv} 2.${gl_bai} 虚拟内存管理 (Swap Manager)"
        echo -e "------------------------------------------------"
        echo -e "${gl_kjlan} 3.${gl_bai} 防火墙/中转管理 (Nftables) ${gl_hong}[核心]${gl_bai}"
        echo -e "${gl_kjlan} 4.${gl_bai} 防暴力破解管理 (Fail2ban) ${gl_hong}[安全]${gl_bai}"
        echo -e "${gl_kjlan} 8.${gl_bai} 核心代理服务 (Xray/Sing-box) ${gl_hong}[Reality]${gl_bai}"
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
            8) proxy_menu ;;
            5) linux_info ;;
            6) linux_update ;;
            7) linux_clean ;;
            9) update_script ;;
            0) echo -e "${gl_lv}再见！${gl_bai}"; exit 0 ;;
            *) echo -e "${gl_hong}无效的选项！${gl_bai}"; sleep 1 ;;
        esac
    done
}

# ===== 脚本入口 =====
if [ "$(id -u)" != "0" ]; then
    echo -e "${gl_hong}错误: 为了执行系统更新和清理，请使用 root 用户运行此脚本！${gl_bai}"
    exit 1
fi

main_menu
