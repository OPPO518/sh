#!/bin/bash

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

# ===== 功能 2: 系统更新 =====
linux_update() {
    echo -e "${gl_huang}正在进行系统更新...${gl_bai}"
    if command -v dnf &>/dev/null; then
        dnf -y update
    elif command -v yum &>/dev/null; then
        yum -y update
    elif command -v apt &>/dev/null; then
        # 简化版apt处理，移除原版复杂的fix_dpkg
        apt update -y
        apt full-upgrade -y
    elif command -v apk &>/dev/null; then
        apk update && apk upgrade
    elif command -v pacman &>/dev/null; then
        pacman -Syu --noconfirm
    elif command -v zypper &>/dev/null; then
        zypper refresh
        zypper update
    else
        echo -e "${gl_hong}未找到支持的包管理器！${gl_bai}"
    fi
}

# ===== 功能 3: 系统清理 =====
linux_clean() {
    echo -e "${gl_huang}正在进行系统清理...${gl_bai}"
    if command -v dnf &>/dev/null; then
        rpm --rebuilddb
        dnf autoremove -y
        dnf clean all
        dnf makecache
    elif command -v yum &>/dev/null; then
        rpm --rebuilddb
        yum autoremove -y
        yum clean all
        yum makecache
    elif command -v apt &>/dev/null; then
        apt autoremove --purge -y
        apt clean -y
        apt autoclean -y
    elif command -v apk &>/dev/null; then
        apk cache clean
        rm -rf /var/log/*
        rm -rf /var/cache/apk/*
        rm -rf /tmp/*
    elif command -v pacman &>/dev/null; then
        pacman -Rns $(pacman -Qdtq) --noconfirm 2>/dev/null
        pacman -Scc --noconfirm
    else
        echo -e "${gl_huang}未找到特定的清理策略，尝试清理通用日志...${gl_bai}"
    fi
    
    # 通用清理
    if command -v journalctl &>/dev/null; then
        journalctl --rotate
        journalctl --vacuum-time=1s
        journalctl --vacuum-size=50M
    fi
}

# ===== 交互逻辑 =====
break_end() {
    echo -e "${gl_lv}操作完成${gl_bai}"
    echo "按回车键返回主菜单..."
    read -r
}

main_menu() {
    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#                                              #"
        echo -e "#          Linux 简易运维工具箱 (纯净版)       #"
        echo -e "#                                              #"
        echo -e "################################################${gl_bai}"
        echo -e "------------------------------------------------"
        echo -e "${gl_lv} 1.${gl_bai} 系统信息查询 (System Info)"
        echo -e "${gl_lv} 2.${gl_bai} 系统更新 (System Update)"
        echo -e "${gl_lv} 3.${gl_bai} 系统清理 (System Clean)"
        echo -e "------------------------------------------------"
        echo -e "${gl_hong} 4.${gl_bai} 退出 (Exit)"
        echo -e "------------------------------------------------"
        
        read -p " 请输入选项 [1-4]: " choice

        case "$choice" in
            1)
                linux_info
                break_end
                ;;
            2)
                linux_update
                break_end
                ;;
            3)
                linux_clean
                break_end
                ;;
            4|0)
                echo -e "${gl_lv}退出脚本。${gl_bai}"
                exit 0
                ;;
            *)
                echo -e "${gl_hong}无效的选项！${gl_bai}"
                sleep 1
                ;;
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
