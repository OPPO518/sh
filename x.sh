#!/bin/bash

# ===== 自我安装与别名清理 =====
# 获取当前脚本的绝对路径
current_script=$(readlink -f "$0")
# 目标路径
target_path="/usr/local/bin/x"

# 如果当前脚本不是在 /usr/local/bin/x 运行，且目标路径与当前不同，则复制过去
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
gl_zi='\033[35m'
gl_kjlan='\033[96m'

# ===== 辅助函数：IP信息获取 =====
ip_address() {
    get_public_ip() {
        curl -s https://ipinfo.io/ip && echo
    }

    get_local_ip() {
        ip route get 8.8.8.8 2>/dev/null | grep -oP 'src \K[^ ]+' || \
        hostname -I 2>/dev/null | awk '{print $1}' || \
        ifconfig 2>/dev/null | grep -E 'inet [0-9]' | grep -v '127.0.0.1' | awk '{print $2}' | head -n1
    }

    public_ip=$(get_public_ip)
    # 移除原版中可能涉及回传的isp检测，仅做本地展示获取
    isp_info=$(curl -s --max-time 3 http://ipinfo.io/org)

    if echo "$isp_info" | grep -Eiq 'mobile|unicom|telecom'; then
        ipv4_address=$(get_local_ip)
    else
        ipv4_address="$public_ip"
    fi
    ipv6_address=$(curl -s --max-time 1 https://v6.ipinfo.io/ip && echo)
}

# ===== 辅助函数：网络流量统计 =====
output_status() {
    output=$(awk 'BEGIN { rx_total = 0; tx_total = 0 }
        $1 ~ /^(eth|ens|enp|eno)[0-9]+/ {
            rx_total += $2
            tx_total += $10
        }
        END {
            rx_units = "Bytes";
            tx_units = "Bytes";
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
    if grep -q 'Alpine' /etc/issue; then
        date +"%Z %z"
    else
        timedatectl | grep "Time zone" | awk '{print $3}'
    fi
}

# ===== 功能模块: 系统初始化 (融合增强版) =====
system_initialize() {
    clear
    echo -e "${gl_kjlan}################################################"
    echo -e "#           系统初始化配置 (System Init)       #"
    echo -e "################################################${gl_bai}"
    
    # 1. 自动检测系统版本
    local os_ver=""
    if grep -q "bullseye" /etc/os-release; then
        os_ver="11"
        echo -e "当前系统: ${gl_huang}Debian 11 (Bullseye)${gl_bai}"
    elif grep -q "bookworm" /etc/os-release; then
        os_ver="12"
        echo -e "当前系统: ${gl_huang}Debian 12 (Bookworm)${gl_bai}"
    else
        echo -e "${gl_hong}错误: 本脚本仅支持 Debian 11 或 12 系统！${gl_bai}"
        read -p "按回车键返回..."
        return
    fi
    
    # [移到这里] 功能说明显示在系统版本下方
    echo -e "${gl_hui}* 包含换源、BBR、时区及落地/中转环境配置${gl_bai}"

    # 2. 询问机器角色 (美化版)
    echo -e "------------------------------------------------"
    echo -e "请设定当前 VPS 的业务角色："
    echo -e "${gl_lv} 1.${gl_bai} 落地机 (Landing)  -> [关闭转发 | 极简安全]"
    echo -e "${gl_lv} 2.${gl_bai} 中转机 (Transit)  -> [开启转发 | 路由优化]"
    echo -e "${gl_hui} 0. 返回主菜单${gl_bai}"
    echo -e "------------------------------------------------"
    read -p "请输入选项 [0-2]: " role_choice

    # 处理返回逻辑
    if [ "$role_choice" == "0" ]; then
        return
    fi

    # 3. 执行核心逻辑
    echo -e "${gl_kjlan}>>> 正在执行初始化，请稍候...${gl_bai}"

    # --- 场景 A: Debian 11 + 落地机 ---
    if [ "$os_ver" == "11" ] && [ "$role_choice" == "1" ]; then
        # [备份与换源]
        [ -f /etc/apt/sources.list ] && mv /etc/apt/sources.list /etc/apt/sources.list.bak_$(date +%F)
        cat > /etc/apt/sources.list << EOF
deb http://deb.debian.org/debian bullseye main contrib non-free
deb http://deb.debian.org/debian bullseye-updates main contrib non-free
deb http://security.debian.org/debian-security bullseye-security main contrib non-free
deb http://archive.debian.org/debian bullseye-backports main contrib non-free
EOF
        # [升级与安装]
        export DEBIAN_FRONTEND=noninteractive
        apt update && apt upgrade -y -o Dpkg::Options::="--force-confold"
        apt install curl wget systemd-timesyncd socat cron rsync -y
        # [内核参数: 落地机]
        rm -f /etc/sysctl.d/99-vps-optimize.conf
        cat > /etc/sysctl.d/99-vps-optimize.conf << EOF
# 开启 BBR
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- 落地机核心安全设置: 关闭转发 ---
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 优化连接数 (防止并发高时丢包)
net.netfilter.nf_conntrack_max = 1000000
net.nf_conntrack_max = 1000000

# 允许 Ping (便于监测)
net.ipv4.icmp_echo_ignore_all = 0
net.ipv6.icmp.echo_ignore_all = 0
EOF
        sysctl --system

    # --- 场景 B: Debian 12 + 落地机 ---
    elif [ "$os_ver" == "12" ] && [ "$role_choice" == "1" ]; then
        # [换源]
        [ -f /etc/apt/sources.list ] && mv /etc/apt/sources.list /etc/apt/sources.list.bak_$(date +%F)
        cat > /etc/apt/sources.list << EOF
deb http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian-security/ bookworm-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian/ bookworm-updates main contrib non-free non-free-firmware
deb http://deb.debian.org/debian/ bookworm-backports main contrib non-free non-free-firmware
EOF
        # [升级与安装]
        export DEBIAN_FRONTEND=noninteractive
        apt update && apt upgrade -y -o Dpkg::Options::="--force-confold"
        apt install curl wget systemd-timesyncd socat cron rsync -y
        # [内核参数: 落地机]
        rm -f /etc/sysctl.d/99-vps-optimize.conf
        cat > /etc/sysctl.d/99-vps-optimize.conf << EOF
# 开启 BBR
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- 落地机核心安全设置: 关闭转发 ---
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# 优化连接数 (防止并发高时丢包)
net.netfilter.nf_conntrack_max = 1000000
net.nf_conntrack_max = 1000000

# 允许 Ping (便于监测)
net.ipv4.icmp_echo_ignore_all = 0
net.ipv6.icmp.echo_ignore_all = 0
EOF
        sysctl --system
        
    # --- 场景 C: Debian 12 + 中转机 ---
    elif [ "$os_ver" == "12" ] && [ "$role_choice" == "2" ]; then
        # [换源]
        [ -f /etc/apt/sources.list ] && mv /etc/apt/sources.list /etc/apt/sources.list.bak_$(date +%F)
        cat > /etc/apt/sources.list << EOF
deb http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian-security/ bookworm-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian/ bookworm-updates main contrib non-free non-free-firmware
deb http://deb.debian.org/debian/ bookworm-backports main contrib non-free non-free-firmware
EOF
        # [升级与安装]
        export DEBIAN_FRONTEND=noninteractive
        apt update && apt upgrade -y -o Dpkg::Options::="--force-confold" --ignore-missing
        apt install curl wget systemd-timesyncd rsync socat -y
        # [内核参数: 中转机]
        rm -f /etc/sysctl.d/99-vps-optimize.conf
        cat > /etc/sysctl.d/99-vps-optimize.conf << EOF
# 开启 BBR
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- 中转机核心功能: 开启转发 ---
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1

# 宽松路由策略 (防止多网卡/隧道环境丢包)
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2

# 优化连接数 (中转机连接数通常是双倍的，必须大)
net.netfilter.nf_conntrack_max = 1000000
net.nf_conntrack_max = 1000000

# 允许 Ping
net.ipv4.icmp_echo_ignore_all = 0
net.ipv6.icmp.echo_ignore_all = 0
EOF
        sysctl --system

    else
        echo -e "${gl_hong}警告: 不支持的组合 (如 Debian 11 + 中转)，操作已取消。${gl_bai}"
        read -p "按回车键返回..."
        return
    fi

    # 4. 通用收尾
    timedatectl set-timezone Asia/Shanghai
    systemctl enable --now systemd-timesyncd

    # 5. 详细结果反馈报告
    echo -e ""
    echo -e "${gl_lv}====== 初始化配置报告 (Init Report) ======${gl_bai}"
    
    # [检查 BBR]
    local bbr_status=$(sysctl -n net.ipv4.tcp_congestion_control)
    echo -e " 1. BBR 算法: \t${gl_kjlan}${bbr_status}${gl_bai}"
    
    # [检查 转发状态]
    local fw_status=$(sysctl -n net.ipv4.ip_forward)
    if [ "$fw_status" == "1" ]; then
        echo -e " 2. 内核转发: \t${gl_huang}已开启 (中转模式)${gl_bai}"
    else
        echo -e " 2. 内核转发: \t${gl_lv}已关闭 (落地模式)${gl_bai}"
    fi

    # [检查 时间]
    local current_time=$(date "+%Y-%m-%d %H:%M:%S")
    echo -e " 3. 当前时间: \t${gl_bai}${current_time} (CST)${gl_bai}"

    echo -e "------------------------------------------------"

    # 6. 重启检测逻辑
    if [ -f /var/run/reboot-required ]; then
        echo -e "${gl_hong}!!! 警告: 检测到内核或系统组件更新，必须重启生效 !!!${gl_bai}"
        echo -e "${gl_hong}!!! Pending Kernel Update Detected !!!${gl_bai}"
        echo -e "------------------------------------------------"
        read -p " 是否立即重启 VPS ? (y/n) [默认 y]: " reboot_choice
        reboot_choice=${reboot_choice:-y}
        if [[ "$reboot_choice" =~ ^[yY]$ ]]; then
            echo -e "${gl_lv}正在执行重启...${gl_bai}"
            reboot
        else
            echo -e "${gl_huang}已跳过重启。请务必稍后手动重启！${gl_bai}"
            read -p "按回车键返回主菜单..."
        fi
    else
        echo -e "${gl_lv}>> 系统状态健康，无需重启。${gl_bai}"
        read -p "按回车键返回主菜单..."
    fi
}

# ===== 功能模块: Swap 虚拟内存管理 =====
swap_management() {
    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#            Swap 虚拟内存管理 (防 OOM 杀进程)     #"
        echo -e "################################################${gl_bai}"
        
        # 实时获取 Swap 状态
        local swap_total=$(free -m | grep Swap | awk '{print $2}')
        local swap_used=$(free -m | grep Swap | awk '{print $3}')
        
        if [ "$swap_total" -eq 0 ]; then
            echo -e "当前状态: ${gl_hong}未启用 Swap${gl_bai}"
        else
            echo -e "当前状态: ${gl_lv}已启用${gl_bai} | 总计: ${gl_kjlan}${swap_total}MB${gl_bai} | 已用: ${gl_huang}${swap_used}MB${gl_bai}"
        fi
        
        echo -e "------------------------------------------------"
        echo -e "${gl_lv} 1.${gl_bai} 添加/扩容 Swap (建议内存的 1-2 倍)"
        echo -e "${gl_hong} 2.${gl_bai} 卸载/关闭 Swap"
        echo -e "------------------------------------------------"
        echo -e "${gl_hui} 0. 返回上级菜单${gl_bai}"
        echo -e "------------------------------------------------"
        
        read -p "请输入选项 [0-2]: " choice

        case "$choice" in
            1)
                echo -e "------------------------------------------------"
                read -p "请输入需要添加的 Swap 大小 (单位: MB，例如 1024): " swap_size
                if [[ ! "$swap_size" =~ ^[0-9]+$ ]]; then
                    echo -e "${gl_hong}错误: 请输入纯数字！${gl_bai}"
                    sleep 1
                    continue
                fi

                echo -e "${gl_huang}正在处理 (清理旧文件 -> 创建新文件)...${gl_bai}"
                # 1. 先清理旧的，防止重复
                swapoff -a 2>/dev/null
                rm -f /swapfile 2>/dev/null
                sed -i '/swapfile/d' /etc/fstab

                # 2. 创建新 Swap (使用 dd 兼容性最佳)
                if dd if=/dev/zero of=/swapfile bs=1M count=$swap_size status=progress; then
                    chmod 600 /swapfile
                    mkswap /swapfile
                    swapon /swapfile
                    # 3. 写入 fstab 实现开机自启
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
            0)
                return
                ;;
            *)
                echo -e "${gl_hong}无效选项${gl_bai}"
                sleep 1
                ;;
        esac
    done
}

# ===== 功能模块: Nftables 防火墙管理 (核心) =====
nftables_management() {
    # --- 内部函数: 自动检测 SSH 端口 (防自锁核心) ---
    detect_ssh_port() {
        # 尝试从 sshd 进程抓取
        local port=$(ss -tlnp | grep 'sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -n 1)
        # 如果抓不到 (比如 sshd 未运行??)，默认兜底 22
        if [ -z "$port" ]; then port="22"; fi
        echo "$port"
    }

    # --- 内部函数: 中转机初始化 (参数全量修正版) ---
    init_transit_firewall() {
        local ssh_port=$(detect_ssh_port)
        echo -e "${gl_huang}检测到 SSH 端口: ${ssh_port} (将强制放行)${gl_bai}"
        echo -e "${gl_kjlan}正在部署 中转机(Transit) 策略 (启用 NAT/Maps)...${gl_bai}"

        # 1. 基础环境清理与安装
        ufw disable 2>/dev/null || true
        apt purge ufw -y 2>/dev/null
        apt update -y && apt install nftables -y
        systemctl enable nftables

        # 2. [核心修正] 全量重写内核参数 (对齐 System Init 中转标准)
        # 确保 rp_filter 和 IPv6 转发都正确开启，防止断流
        echo -e "正在应用中转机内核参数..."
        modprobe nft_nat 2>/dev/null
        modprobe br_netfilter 2>/dev/null
        
        cat > /etc/sysctl.d/99-vps-optimize.conf << EOF
# 开启 BBR
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- 中转机核心: 开启转发 ---
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1

# 宽松路由策略 (解决中转丢包的关键)
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2

# 优化连接数
net.netfilter.nf_conntrack_max = 1000000
net.nf_conntrack_max = 1000000
EOF
        # 立即生效，无需重启
        sysctl --system >/dev/null 2>&1

        # 3. 写入配置 (Maps 映射表)
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
        echo -e "${gl_lv}中转机防火墙部署完成 (内核参数已同步修正)！${gl_bai}"
    }

    # --- 内部函数: 可视化列表 (Bug修复版) ---
    list_rules_ui() {
        echo -e "${gl_huang}=== 防火墙规则概览 (Firewall Status) ===${gl_bai}"
        
        # 1. 显式显示基础保护 (SSH)
        local current_ssh=$(detect_ssh_port)
        echo -e "基础防自锁: ${gl_lv}SSH Port ${current_ssh} [✔ Accepted]${gl_bai}"
        
        # 2. 确定当前使用的表名和集合名
        local table_name=""
        local set_tcp_name=""
        local set_udp_name=""
        
        if nft list tables | grep -q "my_transit"; then 
            table_name="my_transit"
            set_tcp_name="local_tcp"
            set_udp_name="local_udp"
        elif nft list tables | grep -q "my_landing"; then
            table_name="my_landing"
            set_tcp_name="allowed_tcp"
            set_udp_name="allowed_udp"
        else 
            echo -e "${gl_hong}防火墙未初始化${gl_bai}"
            return
        fi

        echo "------------------------------------------------"
        echo -e "${gl_huang}=== 自定义端口放行 (Custom Ports) ===${gl_bai}"

        # 3. 抓取并显示集合内容 (使用 awk 忽略缩进，解决显示为空的 Bug)
        # 逻辑：列出集合 -> 找 elements 行 -> 截取 { 后面的内容 -> 截取 } 前面的内容 -> 去掉空格
        local tcp_list=$(nft list set inet $table_name $set_tcp_name 2>/dev/null | grep 'elements =' | awk -F '{' '{print $2}' | awk -F '}' '{print $1}' | tr -d ' ')
        local udp_list=$(nft list set inet $table_name $set_udp_name 2>/dev/null | grep 'elements =' | awk -F '{' '{print $2}' | awk -F '}' '{print $1}' | tr -d ' ')

        echo -e "[TCP] ${gl_kjlan}${tcp_list:-无}${gl_bai}"
        echo -e "[UDP] ${gl_kjlan}${udp_list:-无}${gl_bai}"
        echo "------------------------------------------------"
        
        # 4. 显示转发规则 (仅中转模式)
        if [ "$table_name" == "my_transit" ]; then
            echo -e "${gl_kjlan}=== 端口转发规则 (IPv4 Forwarding) ===${gl_bai}"
            echo -e "格式: ${gl_hui}本机端口 -> 目标IP : 目标端口${gl_bai}"
            
            echo "--- TCP 转发 ---"
            # 使用 awk 格式化输出，处理冒号和点号
            local tcp_fwd=$(nft list map inet my_transit fwd_tcp | grep ':' | tr -d '\t,' | awk '{printf "Port %-6s -> %s : %s\n", $1, $3, $5}')
            if [ -z "$tcp_fwd" ]; then echo "无"; else echo "$tcp_fwd"; fi
            
            echo "--- UDP 转发 ---"
            local udp_fwd=$(nft list map inet my_transit fwd_udp | grep ':' | tr -d '\t,' | awk '{printf "Port %-6s -> %s : %s\n", $1, $3, $5}')
            if [ -z "$udp_fwd" ]; then echo "无"; else echo "$udp_fwd"; fi
            echo "------------------------------------------------"
        fi
    }

    # --- 菜单循环 ---
    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#          Nftables 防火墙与中转管理           #"
        echo -e "################################################${gl_bai}"
        
        # 动态显示简报
        local ssh_p=$(detect_ssh_port)
        echo -e "当前 SSH 端口: ${gl_lv}${ssh_p}${gl_bai} (自动保护中)"
        
        if nft list tables | grep -q "my_transit"; then
            echo -e "当前模式: ${gl_kjlan}中转机 (Transit NAT)${gl_bai}"
            mode="transit"
            set_tcp="local_tcp"; set_udp="local_udp"
        elif nft list tables | grep -q "my_landing"; then
            echo -e "当前模式: ${gl_huang}落地机 (Landing FW)${gl_bai}"
            mode="landing"
            set_tcp="allowed_tcp"; set_udp="allowed_udp"
        else
            echo -e "当前模式: ${gl_hong}未初始化 / 未知${gl_bai}"
            mode="none"
        fi
        echo -e "------------------------------------------------"
        
        # 根据模式显示菜单
        if [ "$mode" == "none" ]; then
            echo -e "${gl_lv} 1.${gl_bai} 初始化为：落地机防火墙 (仅放行)"
            echo -e "${gl_lv} 2.${gl_bai} 初始化为：中转机防火墙 (含转发面板)"
        else
            echo -e "${gl_hui} > 防火墙规则管理:${gl_bai}"
            echo -e "${gl_lv} 3.${gl_bai} 查看所有规则 (List Rules)"
            echo -e "${gl_lv} 4.${gl_bai} 添加放行端口 (Allow Port)"
            echo -e "${gl_lv} 5.${gl_bai} 删除放行端口 (Delete Port)"
            
            if [ "$mode" == "transit" ]; then
                echo -e "${gl_hui} > 端口转发管理 (Forwarding):${gl_bai}"
                echo -e "${gl_kjlan} 6.${gl_bai} 添加转发规则 (Add Forward)"
                echo -e "${gl_kjlan} 7.${gl_bai} 删除转发规则 (Del Forward)"
            fi
            
            echo -e "------------------------------------------------"
            echo -e "${gl_hong} 8.${gl_bai} 重置/切换模式 (Re-Init)"
        fi
        
        echo -e "------------------------------------------------"
        echo -e "${gl_hui} 0. 返回主菜单${gl_bai}"
        
        read -p "请输入选项: " nf_choice

        case "$nf_choice" in
            1) init_landing_firewall; read -p "按回车继续..." ;;
            2) init_transit_firewall; read -p "按回车继续..." ;;
            3) list_rules_ui; read -p "按回车继续..." ;;
            4) 
                read -p "请输入要放行的 TCP/UDP 端口 (如 8080): " p_port
                if [[ "$p_port" =~ ^[0-9]+$ ]]; then
                    if [ "$mode" == "transit" ]; then table="my_transit"; else table="my_landing"; fi
                    nft add element inet $table $set_tcp { $p_port }
                    nft add element inet $table $set_udp { $p_port }
                    # 持久化
                    nft list ruleset > /etc/nftables.conf
                    echo -e "${gl_lv}端口 $p_port 已放行。${gl_bai}"
                else
                    echo "无效端口"
                fi
                sleep 1
                ;;
            5)
                list_rules_ui
                read -p "请输入要删除的放行端口: " p_port
                if [[ "$p_port" =~ ^[0-9]+$ ]]; then
                    if [ "$mode" == "transit" ]; then table="my_transit"; else table="my_landing"; fi
                    # 尝试删除，即使报错也不影响
                    nft delete element inet $table $set_tcp { $p_port } 2>/dev/null
                    nft delete element inet $table $set_udp { $p_port } 2>/dev/null
                    nft list ruleset > /etc/nftables.conf
                    echo -e "${gl_hong}端口 $p_port 已移除。${gl_bai}"
                fi
                sleep 1
                ;;
            6) # 添加转发 (仅中转)
                if [ "$mode" != "transit" ]; then echo "仅中转模式可用"; sleep 1; continue; fi
                echo -e "请输入转发规则:"
                read -p "1. 本机监听端口 (如 8080): " local_p
                read -p "2. 目标 IP 地址 (如 1.1.1.1): " dest_ip
                read -p "3. 目标端口     (如 80): " dest_p
                
                if [[ -n "$local_p" && -n "$dest_ip" && -n "$dest_p" ]]; then
                    # 写入 Map:  8080 : 1.1.1.1 . 80
                    nft add element inet my_transit fwd_tcp { $local_p : $dest_ip . $dest_p }
                    nft add element inet my_transit fwd_udp { $local_p : $dest_ip . $dest_p }
                    nft list ruleset > /etc/nftables.conf
                    echo -e "${gl_lv}转发规则已添加: :$local_p -> $dest_ip:$dest_p${gl_bai}"
                else
                    echo "输入不完整"
                fi
                read -p "按回车继续..."
                ;;
            7) # 删除转发 (仅中转)
                if [ "$mode" != "transit" ]; then echo "仅中转模式可用"; sleep 1; continue; fi
                list_rules_ui
                read -p "请输入要删除转发的本机端口 (如 8080): " local_p
                if [[ "$local_p" =~ ^[0-9]+$ ]]; then
                    nft delete element inet my_transit fwd_tcp { $local_p } 2>/dev/null
                    nft delete element inet my_transit fwd_udp { $local_p } 2>/dev/null
                    nft list ruleset > /etc/nftables.conf
                    echo -e "${gl_hong}端口 $local_p 的转发规则已移除。${gl_bai}"
                fi
                sleep 1
                ;;
            8) # 重新初始化
                echo -e "${gl_hong}注意: 这将清空当前所有规则并重置模式！${gl_bai}"
                read -p "确定重置吗？(y/n): " confirm
                if [[ "$confirm" == "y" ]]; then
                    echo -e "${gl_huang}正在清除 Nftables 规则...${gl_bai}"
                    
                    # 1. 物理清除内核规则
                    nft flush ruleset
                    
                    # 2. 清空配置文件 (防止重启后旧规则复活)
                    echo "#!/usr/sbin/nft -f" > /etc/nftables.conf
                    echo "flush ruleset" >> /etc/nftables.conf
                    
                    # 3. 重置内部状态
                    mode="none"
                    
                    echo -e "${gl_lv}已重置！现在可以重新选择模式。${gl_bai}"
                    sleep 1
                fi
                ;;
            0) return ;;
            *) echo "无效选项" ;;
        esac
    done
}

# ===== 功能模块: Fail2ban 防爆破管理 =====
fail2ban_management() {
    # --- 内部函数: 检测 SSH 端口 ---
    detect_ssh_port() {
        local port=$(ss -tlnp | grep 'sshd' | awk '{print $4}' | awk -F: '{print $NF}' | head -n 1)
        if [ -z "$port" ]; then port="22"; fi
        echo "$port"
    }

    # --- 内部函数: 安装 Fail2ban ---
    install_fail2ban() {
        local ssh_port=$(detect_ssh_port)
        echo -e "${gl_huang}=== Fail2ban 安装向导 ===${gl_bai}"
        echo -e "当前 SSH 端口: ${gl_lv}${ssh_port}${gl_bai}"
        
        # 1. 询问白名单 (关键防误杀)
        echo -e "------------------------------------------------"
        echo -e "${gl_huang}请输入白名单 IP (防止误封自己/中转机)${gl_bai}"
        echo -e "例如: 1.2.3.4 (多个 IP 用空格隔开)"
        read -p "留空则跳过: " whitelist_ips
        
        # 构造 ignoreip 参数
        local ignore_ip_conf="127.0.0.1/8 ::1"
        if [ -n "$whitelist_ips" ]; then
            ignore_ip_conf="$ignore_ip_conf $whitelist_ips"
        fi

        echo -e "${gl_kjlan}正在安装并配置 Fail2ban...${gl_bai}"
        
        # 2. 安装组件
        apt update && apt install fail2ban rsyslog -y
        systemctl enable --now rsyslog
        touch /var/log/auth.log /var/log/fail2ban.log

        # 3. 配置 Nftables 后端 (物理隔离，不干扰 Docker)
        cat > /etc/fail2ban/jail.d/00-default-nftables.conf << EOF
[DEFAULT]
banaction = nftables-multiport
banaction_allports = nftables-allports
chain = input
EOF

        # 4. 写入 Jail 配置 (动态端口 + 阶梯封禁)
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

        # 5. 清理与重启
        systemctl stop fail2ban >/dev/null 2>&1
        rm -f /var/run/fail2ban/fail2ban.sock
        systemctl daemon-reload
        systemctl restart fail2ban
        systemctl enable fail2ban

        echo -e "${gl_lv}Fail2ban 部署完成！${gl_bai}"
        echo -e "已启用保护: SSH端口 $ssh_port | 白名单: ${whitelist_ips:-无}"
        sleep 2
    }

    # --- 内部函数: 查看状态 ---
    check_f2b_status() {
        if ! systemctl is-active --quiet fail2ban; then
            echo -e "${gl_hong}Fail2ban 未运行！${gl_bai}"; return
        fi
        echo -e "${gl_huang}=== 当前封禁统计 ===${gl_bai}"
        fail2ban-client status sshd
        echo -e "------------------------------------------------"
        fail2ban-client status recidive
    }

    # --- 内部函数: 手动解封 ---
    unban_ip() {
        read -p "请输入要解封的 IP: " target_ip
        if [ -n "$target_ip" ]; then
            fail2ban-client set sshd unbanip $target_ip
            fail2ban-client set recidive unbanip $target_ip
            echo -e "${gl_lv}尝试解封指令已发送。${gl_bai}"
        fi
    }

    # --- 菜单循环 ---
    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#            Fail2ban 防暴力破解管理           #"
        echo -e "################################################${gl_bai}"
        
        # 状态指示灯
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
                echo -e "${gl_huang}正在显示最后 20 条日志 (按 Ctrl+C 退出)...${gl_bai}"
                tail -f -n 20 /var/log/fail2ban.log
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

# ===== 功能 1: 系统信息查询 (已移除统计代码) =====
linux_info() {
    clear
    # [已删除] send_stats "系统信息查询"
    
    echo -e "${gl_huang}正在采集系统信息...${gl_bai}"
    ip_address

    local cpu_info=$(lscpu | awk -F': +' '/Model name:/ {print $2; exit}')
    local cpu_usage_percent=$(awk '{u=$2+$4; t=$2+$4+$5; if (NR==1){u1=u; t1=t;} else printf "%.0f\n", (($2+$4-u1) * 100 / (t-t1))}' \
        <(grep 'cpu ' /proc/stat) <(sleep 1; grep 'cpu ' /proc/stat))
    local cpu_cores=$(nproc)
    local cpu_freq=$(cat /proc/cpuinfo | grep "MHz" | head -n 1 | awk '{printf "%.1f GHz\n", $4/1000}')
    local mem_info=$(free -b | awk 'NR==2{printf "%.2f/%.2fM (%.2f%%)", $3/1024/1024, $2/1024/1024, $3*100/$2}')
    local disk_info=$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}')
    
    # 仅保留纯粹的信息获取，不发送数据
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
    echo -e "${gl_kjlan}主机名:         ${gl_bai}$hostname"
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
}

# ===== 功能 2: 系统更新 (Debian专用 + 重启检测) =====
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
}

# ===== 功能 3: 系统清理 (Debian专用) =====
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
}

# ===== 功能 4: 脚本更新 =====
update_script() {
    echo -e "${gl_huang}正在检查并更新脚本...${gl_bai}"
    # 这里的 URL 换成你自己的 GitHub Raw 地址
    sh_url="https://raw.githubusercontent.com/OPPO518/sh/main/x.sh"
    
    # 下载新版本覆盖旧版本
    if curl -sS -o /usr/local/bin/x "$sh_url"; then
        chmod +x /usr/local/bin/x
        echo -e "${gl_lv}更新成功！正在重启脚本...${gl_bai}"
        sleep 1
        # 重新执行新脚本
        exec /usr/local/bin/x
    else
        echo -e "${gl_hong}更新失败，请检查网络或 GitHub 链接！${gl_bai}"
    fi
}

# ===== 交互逻辑 =====
break_end() {
    echo -e "${gl_lv}操作完成${gl_bai}"
    echo "按回车键返回主菜单..."
    read -r
}

# ===== 主菜单 =====
main_menu() {
    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#                                              #"
        echo -e "#           Debian VPS 极简运维工具箱          #"
        echo -e "#                                              #"
        echo -e "################################################${gl_bai}"
        echo -e "${gl_huang}当前版本: 1.6 (Nftables Manager)${gl_bai}"
        echo -e "------------------------------------------------"
        echo -e "${gl_lv} 1.${gl_bai} 系统初始化 (System Init) ${gl_hong}[新机必点]${gl_bai}"
        echo -e "${gl_lv} 2.${gl_bai} 虚拟内存管理 (Swap Manager)"
        echo -e "------------------------------------------------"
        echo -e "${gl_kjlan} 3.${gl_bai} 防火墙/中转管理 (Nftables) ${gl_hong}[核心]${gl_bai}"
        echo -e "${gl_kjlan} 4.${gl_bai} 防暴力破解管理 (Fail2ban) ${gl_hong}[安全]${gl_bai}"
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
            5) linux_info; break_end ;;
            6) linux_update; break_end ;;
            7) linux_clean; break_end ;;
            9) update_script ;;
            0) echo -e "${gl_lv}再见！${gl_bai}"; exit 0 ;;
            *) echo -e "${gl_hong}无效的选项！${gl_bai}"; sleep 1 ;;
        esac
    done
}

# ===== 脚本入口 =====
# 检查root权限
if [ "$(id -u)" != "0" ]; then
    echo -e "${gl_hong}错误: 为了执行系统更新和清理，请使用 root 用户运行此脚本！${gl_bai}"
    exit 1
fi

main_menu
