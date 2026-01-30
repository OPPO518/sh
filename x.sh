#!/bin/bash

# ==================================================
# 脚本名称: Linux 简易运维工具箱 (Debian 专用版)
# 功能: 系统信息/更新/清理 + 初始化 (UI样式已还原)
# 快捷指令: x
# ==================================================

# ===== 全局配置 =====
UPDATE_URL="https://raw.githubusercontent.com/OPPO518/sh/main/x.sh"

# 颜色变量
gl_hong='\033[31m'
gl_lv='\033[32m'
gl_huang='\033[33m'
gl_lan='\033[34m'
gl_bai='\033[0m'
gl_kjlan='\033[96m'

# ===== 0. 环境检查 =====
check_debian() {
    if ! command -v apt &>/dev/null; then
        echo -e "${gl_hong}错误: 本脚本仅支持 Debian/Ubuntu 系系统 (未检测到 apt)！${gl_bai}"
        exit 1
    fi
}
check_debian

# ===== 1. 自我安装逻辑 =====
install_self() {
    current_path=$(readlink -f "$0")
    target_path="/usr/local/bin/x"
    if [ -f "$current_path" ] && [ "$current_path" != "$target_path" ]; then
        cp -f "$current_path" "$target_path"
        chmod +x "$target_path"
    fi
}
install_self

# ===== 2. 辅助函数 =====
output_status() {
    output=$(awk 'BEGIN { rx_total = 0; tx_total = 0 }
        $1 ~ /^(eth|ens|enp|eno)[0-9]+/ { rx_total += $2; tx_total += $10 }
        END {
            rx_units = "B"; tx_units = "B";
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "KB"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "MB"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "GB"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "KB"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "MB"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "GB"; }
            printf("%.2f%s %.2f%s\n", rx_total, rx_units, tx_total, tx_units);
        }' /proc/net/dev)
    rx=$(echo "$output" | awk '{print $1}')
    tx=$(echo "$output" | awk '{print $2}')
}

ip_address() {
    get_public_ip() { curl -s https://ipinfo.io/ip && echo; }
    public_ip=$(get_public_ip)
    ipv4_address="$public_ip"
    ipv6_address=$(curl -s --max-time 1 https://v6.ipinfo.io/ip && echo)
}

current_timezone() {
    timedatectl | grep "Time zone" | awk '{print $3}'
}

# ===== 3. 核心功能模块 =====

# [功能1] 系统信息 (已还原为经典排版)
linux_info() {
    clear
    echo -e "${gl_huang}正在采集系统信息...${gl_bai}"
    ip_address
    output_status

    local cpu_info=$(lscpu | awk -F': +' '/Model name:/ {print $2; exit}')
    local cpu_usage_percent=$(awk '{u=$2+$4; t=$2+$4+$5; if (NR==1){u1=u; t1=t;} else printf "%.0f\n", (($2+$4-u1) * 100 / (t-t1))}' \
        <(grep 'cpu ' /proc/stat) <(sleep 1; grep 'cpu ' /proc/stat))
    local cpu_cores=$(nproc)
    local cpu_freq=$(cat /proc/cpuinfo | grep "MHz" | head -n 1 | awk '{printf "%.1f GHz\n", $4/1000}')
    local mem_info=$(free -b | awk 'NR==2{printf "%.2f/%.2fM (%.2f%%)", $3/1024/1024, $2/1024/1024, $3*100/$2}')
    local disk_info=$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}')
    
    local load=$(uptime | awk '{print $(NF-2), $(NF-1), $NF}')
    local cpu_arch=$(uname -m)
    local hostname=$(uname -n)
    local kernel_version=$(uname -r)
    local congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
    local queue_algorithm=$(sysctl -n net.core.default_qdisc)
    local os_info=$(grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | tr -d '"')
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
    if [ -n "$ipv4_address" ]; then
        echo -e "${gl_kjlan}IPv4地址:       ${gl_bai}$ipv4_address"
    fi
    if [ -n "$ipv6_address" ]; then
        echo -e "${gl_kjlan}IPv6地址:       ${gl_bai}$ipv6_address"
    fi
    echo -e "${gl_kjlan}地理位置:       ${gl_bai}$timezone"
    echo -e "${gl_kjlan}系统时间:       ${gl_bai}$current_time"
    echo -e "${gl_kjlan}-------------"
    echo -e "${gl_kjlan}运行时长:       ${gl_bai}$runtime"
    echo
}

# [功能2] 系统更新 (仅 APT)
linux_update() {
    echo -e "${gl_huang}正在更新 Debian 系统软件包...${gl_bai}"
    export DEBIAN_FRONTEND=noninteractive
    apt update -y && apt full-upgrade -y -o Dpkg::Options::="--force-confold"
    echo -e "${gl_lv}系统更新完成！${gl_bai}"
}

# [功能3] 系统清理 (仅 APT + 日志)
linux_clean() {
    echo -e "${gl_huang}正在清理系统垃圾...${gl_bai}"
    apt autoremove --purge -y
    apt clean -y
    if command -v journalctl &>/dev/null; then
        journalctl --rotate
        journalctl --vacuum-time=1s
        journalctl --vacuum-size=50M
    fi
    find /tmp -type f -atime +10 -delete 2>/dev/null
    echo -e "${gl_lv}清理完成！${gl_bai}"
}

# [功能4] 系统初始化 (Debian 11/12 智能适配)
system_init() {
    echo -e "${gl_huang}正在执行系统初始化配置...${gl_bai}"
    
    # 获取系统代号
    if [ -f /etc/os-release ]; then
        OS_CODENAME=$(grep VERSION_CODENAME /etc/os-release | cut -d= -f2 | tr -d '"')
    fi
    
    echo "检测到系统版本: Debian $OS_CODENAME"
    [ -f /etc/apt/sources.list ] && cp /etc/apt/sources.list /etc/apt/sources.list.bak_$(date +%F)
    
    if [ "$OS_CODENAME" == "bookworm" ]; then
        cat > /etc/apt/sources.list << EOF
deb http://deb.debian.org/debian/ bookworm main contrib non-free non-free-firmware
deb http://deb.debian.org/debian-security/ bookworm-security main contrib non-free non-free-firmware
deb http://deb.debian.org/debian/ bookworm-updates main contrib non-free non-free-firmware
deb http://deb.debian.org/debian/ bookworm-backports main contrib non-free non-free-firmware
EOF
    elif [ "$OS_CODENAME" == "bullseye" ]; then
        cat > /etc/apt/sources.list << EOF
deb http://deb.debian.org/debian bullseye main contrib non-free
deb http://deb.debian.org/debian bullseye-updates main contrib non-free
deb http://security.debian.org/debian-security bullseye-security main contrib non-free
deb http://archive.debian.org/debian bullseye-backports main contrib non-free
EOF
    else
        echo -e "${gl_hong}注意: 非标准 Debian 11/12，跳过换源步骤，仅执行优化。${gl_bai}"
    fi

    echo "正在更新系统并安装基础工具..."
    export DEBIAN_FRONTEND=noninteractive
    apt update && apt upgrade -y -o Dpkg::Options::="--force-confold" --ignore-missing
    apt install -y curl wget vim git tar unzip net-tools dnsutils ca-certificates socat cron rsync systemd-timesyncd

    echo "正在配置全局内核参数 (BBR + 双栈转发)..."
    rm -f /etc/sysctl.d/99-vps-optimize.conf

    cat > /etc/sysctl.d/99-vps-optimize.conf << EOF
# 开启 BBR 加速
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 开启双栈内核转发
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv6.conf.default.forwarding = 1

# 允许 ICMP 响应 (Ping)
net.ipv4.icmp_echo_ignore_all = 0
net.ipv6.icmp.echo_ignore_all = 0

# 优化 IPv6 与禁用反向路径过滤
net.ipv6.conf.all.disable_ipv6 = 0
net.ipv6.conf.default.disable_ipv6 = 0
net.ipv6.conf.all.accept_ra = 2
net.ipv6.conf.default.accept_ra = 2
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
EOF

    sysctl --system
    timedatectl set-timezone Asia/Shanghai
    systemctl enable --now systemd-timesyncd

    echo -e "${gl_lv}--- 初始化完成 ---${gl_bai}"
    echo -e "BBR 状态: $(sysctl -n net.ipv4.tcp_congestion_control)"
    echo -e "转发状态: IPv4->$(sysctl -n net.ipv4.ip_forward) | IPv6->$(sysctl -n net.ipv6.conf.all.forwarding)"
}

# [功能5] 脚本自我更新
update_script() {
    echo -e "${gl_huang}正在更新脚本...${gl_bai}"
    if curl -sS -o /usr/local/bin/x "$UPDATE_URL"; then
        chmod +x /usr/local/bin/x
        echo -e "${gl_lv}更新成功！正在重启...${gl_bai}"
        sleep 1
        exec /usr/local/bin/x
    else
        echo -e "${gl_hong}更新失败！${gl_bai}"
    fi
}

# ===== 4. 主菜单 =====
break_end() {
    echo -e "${gl_lv}操作完成${gl_bai}"
    echo "按回车键返回主菜单..."
    read -r
}

main_menu() {
    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#         Linux 简易运维工具箱 (Debian专用版)   #"
        echo -e "################################################${gl_bai}"
        echo -e "${gl_huang}快捷命令: x${gl_bai}"
        echo -e "------------------------------------------------"
        echo -e "${gl_lv} 1.${gl_bai} 系统信息查询"
        echo -e "${gl_lv} 2.${gl_bai} 系统更新 (APT Update)"
        echo -e "${gl_lv} 3.${gl_bai} 系统清理 (APT Clean)"
        echo -e "------------------------------------------------"
        echo -e "${gl_lan} 4.${gl_bai} 系统初始化 (换源/BBR/转发/工具)"
        echo -e "------------------------------------------------"
        echo -e "${gl_kjlan} 5.${gl_bai} 更新脚本 (Update Script)"
        echo -e "${gl_hong} 0.${gl_bai} 退出"
        echo -e "------------------------------------------------"
        
        read -p " 请输入选项: " choice

        case "$choice" in
            1) linux_info; break_end ;;
            2) linux_update; break_end ;;
            3) linux_clean; break_end ;;
            4) system_init; break_end ;;
            5) update_script ;;
            0) exit 0 ;;
            *) echo "无效选项"; sleep 1 ;;
        esac
    done
}

if [ "$(id -u)" != "0" ]; then
    echo -e "${gl_hong}请使用 root 运行！${gl_bai}"
    exit 1
fi

main_menu
