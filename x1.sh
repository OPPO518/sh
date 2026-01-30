#!/bin/bash

# ==================================================
# 脚本名称: Linux 简易运维工具箱 (纯净版)
# 功能: 系统信息、系统更新、系统清理、在线更新
# 快捷指令: x
# ==================================================

# ===== 全局配置 =====
# 你的 GitHub 仓库 Raw 地址 (用于自我更新)
UPDATE_URL="https://raw.githubusercontent.com/OPPO518/sh/main/x.sh"

# 颜色变量
gl_hong='\033[31m'
gl_lv='\033[32m'
gl_huang='\033[33m'
gl_lan='\033[34m'
gl_bai='\033[0m'
gl_kjlan='\033[96m'

# ===== 1. 自我安装逻辑 =====
# 自动将脚本安装到 /usr/local/bin/x，实现全局命令 'x'
install_self() {
    current_path=$(readlink -f "$0")
    target_path="/usr/local/bin/x"
    
    # 如果当前不在目标路径，且目标路径不存在或内容不同，则复制
    if [ "$current_path" != "$target_path" ]; then
        # cp -f "$current_path" "$target_path"
        # 为了兼容 curl | bash 运行方式，直接下载一份新的或是移动
        if [ -f "$current_path" ]; then
            cp -f "$current_path" "$target_path"
            chmod +x "$target_path"
        fi
    fi
}
install_self

# ===== 2. 辅助函数 =====
# 网络流量统计
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

# IP信息获取
ip_address() {
    get_public_ip() { curl -s https://ipinfo.io/ip && echo; }
    public_ip=$(get_public_ip)
    ipv4_address="$public_ip"
}

# ===== 3. 核心功能模块 =====

# [功能1] 系统信息
linux_info() {
    clear
    echo -e "${gl_huang}正在采集系统信息...${gl_bai}"
    ip_address
    output_status
    
    local cpu_info=$(lscpu | awk -F': +' '/Model name:/ {print $2; exit}')
    local cpu_usage=$(awk '{u=$2+$4; t=$2+$4+$5; if (NR==1){u1=u; t1=t;} else printf "%.0f\n", (($2+$4-u1) * 100 / (t-t1))}' <(grep 'cpu ' /proc/stat) <(sleep 1; grep 'cpu ' /proc/stat))
    local mem_info=$(free -m | awk 'NR==2{printf "%s/%sMB (%.2f%%)", $3, $2, $3*100/$2}')
    local disk_info=$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}')
    local os_info=$(grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | tr -d '"')
    local hostname=$(uname -n)
    local tcp_count=$(ss -t | wc -l)

    echo ""
    echo -e "${gl_lv}=== 系统状态面板 ===${gl_bai}"
    echo -e "${gl_kjlan}主机名:     ${gl_bai}$hostname"
    echo -e "${gl_kjlan}系统版本:   ${gl_bai}$os_info"
    echo -e "${gl_kjlan}CPU型号:    ${gl_bai}$cpu_info"
    echo -e "${gl_kjlan}CPU占用:    ${gl_bai}$cpu_usage%"
    echo -e "${gl_kjlan}内存使用:   ${gl_bai}$mem_info"
    echo -e "${gl_kjlan}硬盘使用:   ${gl_bai}$disk_info"
    echo -e "${gl_kjlan}网络流量:   ${gl_bai}入:$rx  出:$tx"
    echo -e "${gl_kjlan}TCP连接:    ${gl_bai}$tcp_count"
    echo -e "${gl_kjlan}公网IP:     ${gl_bai}$ipv4_address"
    echo ""
}

# [功能2] 系统更新
linux_update() {
    echo -e "${gl_huang}正在更新系统软件包...${gl_bai}"
    if command -v dnf &>/dev/null; then dnf -y update
    elif command -v yum &>/dev/null; then yum -y update
    elif command -v apt &>/dev/null; then apt update -y && apt full-upgrade -y
    elif command -v apk &>/dev/null; then apk update && apk upgrade
    elif command -v pacman &>/dev/null; then pacman -Syu --noconfirm
    else echo -e "${gl_hong}未找到支持的包管理器！${gl_bai}"; fi
}

# [功能3] 系统清理
linux_clean() {
    echo -e "${gl_huang}正在清理系统垃圾...${gl_bai}"
    
    # 包管理器清理
    if command -v dnf &>/dev/null; then dnf autoremove -y && dnf clean all
    elif command -v yum &>/dev/null; then yum autoremove -y && yum clean all
    elif command -v apt &>/dev/null; then apt autoremove --purge -y && apt clean -y
    elif command -v apk &>/dev/null; then apk cache clean
    elif command -v pacman &>/dev/null; then pacman -Scc --noconfirm
    fi

    # 日志清理
    if command -v journalctl &>/dev/null; then
        echo "清理 journal 日志 (保留50M)..."
        journalctl --rotate
        journalctl --vacuum-time=1s
        journalctl --vacuum-size=50M
    fi
    
    # 临时文件清理
    echo "清理 /tmp 过期文件..."
    find /tmp -type f -atime +10 -delete 2>/dev/null
}

# [功能4] 脚本自我更新
update_script() {
    echo -e "${gl_huang}正在从 GitHub 拉取最新版本...${gl_bai}"
    echo -e "源地址: $UPDATE_URL"
    
    if curl -sS -o /usr/local/bin/x "$UPDATE_URL"; then
        chmod +x /usr/local/bin/x
        echo -e "${gl_lv}更新成功！正在重启脚本...${gl_bai}"
        sleep 1
        exec /usr/local/bin/x
    else
        echo -e "${gl_hong}更新失败，请检查网络或 GitHub 链接是否正确！${gl_bai}"
        sleep 2
    fi
}

# ===== 4. 主菜单与入口 =====
break_end() {
    echo -e "${gl_lv}操作完成${gl_bai}"
    echo "按回车键返回主菜单..."
    read -r
}

main_menu() {
    while true; do
        clear
        echo -e "${gl_kjlan}################################################"
        echo -e "#            Linux 简易运维工具箱 (精简版)     #"
        echo -e "################################################${gl_bai}"
        echo -e "${gl_huang}快捷命令: x${gl_bai}"
        echo -e "------------------------------------------------"
        echo -e "${gl_lv} 1.${gl_bai} 系统信息查询"
        echo -e "${gl_lv} 2.${gl_bai} 系统更新"
        echo -e "${gl_lv} 3.${gl_bai} 系统清理"
        echo -e "${gl_lv} 4.${gl_bai} 更新脚本 (Update Script)"
        echo -e "------------------------------------------------"
        echo -e "${gl_hong} 0.${gl_bai} 退出"
        echo -e "------------------------------------------------"
        
        read -p " 请输入选项 [0-4]: " choice

        case "$choice" in
            1) linux_info; break_end ;;
            2) linux_update; break_end ;;
            3) linux_clean; break_end ;;
            4) update_script ;;
            0) echo -e "${gl_lv}Bye!${gl_bai}"; exit 0 ;;
            *) echo -e "${gl_hong}无效选项${gl_bai}"; sleep 1 ;;
        esac
    done
}

# 检查 Root 权限
if [ "$(id -u)" != "0" ]; then
    echo -e "${gl_hong}错误: 请使用 root 用户运行此脚本！${gl_bai}"
    exit 1
fi

# 启动菜单
main_menu
