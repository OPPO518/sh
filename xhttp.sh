#!/bin/bash

DEFAULT_START_PORT=20000
IP_ADDRESSES=($(hostname -I))

# 升级版 ask_yn：支持回车直接返回默认值
ask_yn() {
    local prompt="$1"
    local default="$2"
    local answer
    while true; do
        if [[ "$default" == "y" ]]; then
            read -p "$prompt [Y/n]: " answer >&2
        else
            read -p "$prompt [y/N]: " answer >&2
        fi
        answer=${answer:-$default}
        case "$answer" in
            y|Y) echo "y"; return ;;
            n|N) echo "n"; return ;;
            *) echo "请输入 y 或 n." >&2 ;;
        esac
    done
}

validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && (( port>=1 && port<=65535 ))
}

validate_hex_len() {
    local val="$1"
    local len="${#val}"
    [[ "$val" =~ ^[0-9a-fA-F]+$ ]] && (( len>=8 && len<=16 ))
}

validate_path() {
    [[ "$1" =~ ^/[^[:space:]]*$ ]]
}

install_xHTTP() {
    echo "安装最新 Xray（重命名为 xHTTP）..."
    apt-get install -y curl unzip openssl 2>/dev/null || yum install -y curl unzip openssl 2>/dev/null

    echo "下载最新 Xray 内核..."
    curl -L -o xray.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip

    unzip -o xray.zip
    mv xray /usr/local/bin/xHTTP
    chmod +x /usr/local/bin/xHTTP

    cat <<EOF >/etc/systemd/system/xHTTP.service
[Unit]
Description=xHTTP Service
After=network.target

[Service]
ExecStart=/usr/local/bin/xHTTP -c /etc/xHTTP/config.toml
Restart=on-failure
User=nobody
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable xHTTP.service
}

filter_valid_ips() {
    valid_ips=()
    for ip in "${IP_ADDRESSES[@]}"; do
        if [[ $ip =~ ^127\. ]] || [[ $ip =~ ^10\. ]] || [[ $ip =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] || [[ $ip =~ ^192\.168\. ]] || [[ $ip =~ ^::1$ ]] || [[ $ip =~ ^fe80: ]]; then
            continue
        fi
        valid_ips+=("$ip")
    done
    IP_ADDRESSES=("${valid_ips[@]}")
}

############################################
# WARP 手动配置 (用于防溯源与 IPv4 兜底)
############################################
input_warp_keys() {
    echo "================================================="
    echo "请输入配置 WARP 所需的参数"
    echo "================================================="
    while true; do
        read -p "请输入可用的 WARP secretKey (例如: gKcCAxJWa...): " WARP_PRIVATE_KEY
        WARP_PRIVATE_KEY=$(echo "$WARP_PRIVATE_KEY" | tr -d '" ')
        [[ -n "$WARP_PRIVATE_KEY" ]] && break
    done

    while true; do
        read -p "请输入 WARP 内网 IPv4 地址 (例如: 172.16.0.2/32): " WARP_IPV4
        WARP_IPV4=$(echo "$WARP_IPV4" | tr -d '[]" ')
        [[ -n "$WARP_IPV4" ]] && break
    done

    while true; do
        read -p "请输入 WARP reserved 数组 (例如: 71, 68, 150): " WARP_RESERVED
        WARP_RESERVED=$(echo "$WARP_RESERVED" | tr -d '[]"')
        [[ -n "$WARP_RESERVED" ]] && break
    done

    WARP_ENABLE=true
    echo "WARP 参数已记录。"
    echo "================================================="
}

############################################
# 新版 Reality 密钥解析
############################################
generate_reality_keys() {
    echo ">> 自动生成 Reality 密钥..."
    key_output=$(/usr/local/bin/xHTTP x25519 2>/dev/null)

    PRIVATE_KEY=$(echo "$key_output" | grep -i 'PrivateKey' | awk -F': ' '{print $2}' | tr -d ' ')
    PUBLIC_KEY=$(echo "$key_output" | grep -i 'Password' | awk -F': ' '{print $2}' | tr -d ' ')

    if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
        echo "Reality 密钥解析失败，请检查 xHTTP x25519 输出格式"
        exit 1
    fi
}

interactive_params() {
    custom_config=$(ask_yn "是否需要自定义 xHTTP 配置参数？(选 n 将全部自动生成)" "n")

    if [[ "$custom_config" == "y" ]]; then
        echo "================================================="
        echo "提示：接下来的设置中，如果你不想输入，直接按回车即可自动生成。"
        echo "================================================="
        
        read -p "请输入伪装站点 (直接回车默认: www.cloudflare.com): " REALITY_TARGET
        REALITY_TARGET=${REALITY_TARGET:-"www.cloudflare.com"}

        read -p "请输入 UUID (直接回车默认自动生成): " GLOBAL_UUID
        GLOBAL_UUID=${GLOBAL_UUID:-$(/usr/local/bin/xHTTP uuid)}

        read -p "请输入 Reality 私钥 (直接回车默认自动生成): " PRIVATE_KEY
        if [[ -z "$PRIVATE_KEY" ]]; then
            generate_reality_keys
        else
            read -p "请输入配套的 Reality 公钥: " PUBLIC_KEY
            if [[ -z "$PUBLIC_KEY" ]]; then
                echo "公钥不能为空，已回退为自动生成完整的 Reality 密钥对..."
                generate_reality_keys
            fi
        fi

        read -p "请输入 shortId [8-16位 16进制] (直接回车默认自动生成): " SHORT_ID
        if [[ -z "$SHORT_ID" ]] || ! validate_hex_len "$SHORT_ID"; then
            SHORT_ID=$(openssl rand -hex 8)
            echo ">> 自动生成 shortId: $SHORT_ID"
        fi

        read -p "请输入 XHTTP path [需以 / 开头] (直接回车默认自动生成): " XHTTP_PATH
        if [[ -z "$XHTTP_PATH" ]] || ! validate_path "$XHTTP_PATH"; then
            XHTTP_PATH="/Client_upload_$(openssl rand -hex 4)"
            echo ">> 自动生成 path: $XHTTP_PATH"
        fi
    else
        REALITY_TARGET="www.cloudflare.com"
        GLOBAL_UUID=$(/usr/local/bin/xHTTP uuid)
        generate_reality_keys
        SHORT_ID=$(openssl rand -hex 8)
        XHTTP_PATH="/Client_upload_$(openssl rand -hex 4)"
    fi

    echo "================================================="

    custom_port=$(ask_yn "是否使用默认起始端口 $DEFAULT_START_PORT？" "y")
    if [[ "$custom_port" == "n" ]]; then
        while true; do
            read -p "请输入自定义起始端口 (1-65535): " START_PORT
            if validate_port "$START_PORT"; then
                break
            else
                echo "端口格式错误，必须为 1-65535 之间的数字."
            fi
        done
    else
        START_PORT=$DEFAULT_START_PORT
    fi
}

config_xHTTP() {
    mkdir -p /etc/xHTTP
    filter_valid_ips
    
    WARP_ENABLE=false
    HAS_IPV6=false
    for ip in "${IP_ADDRESSES[@]}"; do
        if [[ "$ip" == *":"* ]]; then
            HAS_IPV6=true
            break
        fi
    done

    if [ "$HAS_IPV6" = true ]; then
        echo "================================================="
        echo "【检测到存在 IPv6 地址，必须配置 WARP 作为 IPv4 兜底】"
        echo "================================================="
        input_warp_keys
    else
        add_warp=$(ask_yn "检测到当前仅有 IPv4 地址，是否需要增加 WARP 配置 (用于防溯源隔离大陆流量/隐藏真实 IP)？" "n")
        if [[ "$add_warp" == "y" ]]; then
            input_warp_keys
        fi
    fi

    interactive_params

    config_content="[routing]
domainStrategy = \"IPIfNonMatch\"

"
    inbounds_section=""
    outbounds_section=""
    routing_section=""
    ipv6_inbounds=()

    if [ "$WARP_ENABLE" = true ]; then
        # 本地探针 SOCKS5 入站
        inbounds_section+="[[inbounds]]
listen = \"127.0.0.1\"
port = 40000
protocol = \"socks\"
tag = \"socks-local\"
[inbounds.settings]
auth = \"noauth\"
udp = true

"
        # 1. 第一层防御：探针与全局 CN 防溯源隔离 (最高优先级)
        routing_section+="[[routing.rules]]
type = \"field\"
inboundTag = [\"socks-local\"]
outboundTag = \"warp-ipv4\"

[[routing.rules]]
type = \"field\"
domain = [\"geosite:cn\"]
outboundTag = \"warp-ipv4\"

[[routing.rules]]
type = \"field\"
ip = [\"geoip:cn\"]
outboundTag = \"warp-ipv4\"

"
        outbounds_section+="[[outbounds]]
tag = \"warp-ipv4\"
protocol = \"wireguard\"

[outbounds.settings]
mtu = 1420
secretKey = \"$WARP_PRIVATE_KEY\"
address = [\"$WARP_IPV4\"]
workers = 2
domainStrategy = \"ForceIPv4\"
reserved = [$WARP_RESERVED]
noKernelTun = true

[[outbounds.settings.peers]]
publicKey = \"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\"
allowedIPs = [\"0.0.0.0/0\"]
endpoint = \"engage.cloudflareclient.com:2408\"
keepAlive = 25

"
    fi

    index=0
    v2rayn_links=""

    MAIN_IP="${IP_ADDRESSES[0]}"
    if [[ "$MAIN_IP" == *:* ]]; then
        CONN_IP="[$MAIN_IP]"
    else
        CONN_IP="$MAIN_IP"
    fi

    for ip in "${IP_ADDRESSES[@]}"; do
        port=$((START_PORT + index))
        in_tag="in_$((index+1))"
        out_tag="out_$((index+1))"
        uuid="$GLOBAL_UUID"

        inbounds_section+="[[inbounds]]
port = $port
protocol = \"vless\"
tag = \"$in_tag\"

[inbounds.settings]
decryption = \"none\"

[[inbounds.settings.clients]]
id = \"$uuid\"

[inbounds.streamSettings]
network = \"xhttp\"
security = \"reality\"

[inbounds.streamSettings.xhttpSettings]
path = \"$XHTTP_PATH\"
mode = \"auto\"

[inbounds.streamSettings.realitySettings]
show = false
dest = \"$REALITY_TARGET:443\"
serverNames = [\"$REALITY_TARGET\"]
privateKey = \"$PRIVATE_KEY\"
shortIds = [\"$SHORT_ID\"]

"
        outbounds_section+="[[outbounds]]
sendThrough = \"$ip\"
protocol = \"freedom\"
tag = \"$out_tag\"

[outbounds.settings]
"
        if [[ "$ip" == *":"* ]]; then
            ipv6_inbounds+=("\"$in_tag\"")
            outbounds_section+="domainStrategy = \"UseIPv6\"

"
            # 2. 第二层防御：IPv6 节点的 Google/YouTube VIP 直通快车道
            routing_section+="[[routing.rules]]
type = \"field\"
inboundTag = [\"$in_tag\"]
domain = [\"geosite:google\", \"geosite:youtube\"]
outboundTag = \"$out_tag\"

"
            # 3. 第三层：IPv6 常规原生链路
            routing_section+="[[routing.rules]]
type = \"field\"
inboundTag = [\"$in_tag\"]
ip = [\"::/0\"]
outboundTag = \"$out_tag\"

"
        else
            outbounds_section+="domainStrategy = \"UseIPv4\"

"
            # 5. 第五层：IPv4 原生直连 (兜底)
            routing_section+="[[routing.rules]]
type = \"field\"
inboundTag = [\"$in_tag\"]
outboundTag = \"$out_tag\"

"
        fi

        spx_enc=$(echo -n "$XHTTP_PATH" | sed 's/\//%2F/g')
        v2rayn_link="vless://$uuid@$CONN_IP:$port?encryption=none&flow=&type=xhttp&mode=auto&security=reality&pbk=$PUBLIC_KEY&sid=$SHORT_ID&fp=chrome&path=$spx_enc&sni=$REALITY_TARGET#xHTTP-${ip}"
        v2rayn_links+="$v2rayn_link\n"

        index=$((index+1))
    done

    # 4. 第四层：IPv6 节点的 WARP 终极兜底 (解决纯 IPv4 网站断连)
    if [ "$WARP_ENABLE" = true ] && [ ${#ipv6_inbounds[@]} -gt 0 ]; then
        ipv6_inbounds_str=$(IFS=, ; echo "${ipv6_inbounds[*]}")
        routing_section+="[[routing.rules]]
type = \"field\"
inboundTag = [$ipv6_inbounds_str]
ip = [\"0.0.0.0/0\"]
outboundTag = \"warp-ipv4\"

"
    fi

    END_PORT=$((START_PORT + index - 1))

    config_content="${config_content}${inbounds_section}${outbounds_section}${routing_section}"
    echo -e "$config_content" >/etc/xHTTP/config.toml
    
    {
        echo "IP: $MAIN_IP"
        if [ "$START_PORT" -eq "$END_PORT" ]; then
            echo "端口: $START_PORT"
        else
            echo "端口: $START_PORT-$END_PORT"
        fi
        echo "UUID: $GLOBAL_UUID"
        echo "Reality 公钥: $PUBLIC_KEY"
        echo "伪装站点: $REALITY_TARGET"
        echo "ShortID: $SHORT_ID"
        echo "XHTTP Path: $XHTTP_PATH"
        echo "v2rayN 链接:"
        echo -e "$v2rayn_links"
    } > /etc/xHTTP/clients.txt

    systemctl restart xHTTP.service
    
    echo ""
    echo "================================================="
    echo "        Reality + XHTTP 配置生成成功             "
    echo "================================================="
    systemctl --no-pager status xHTTP.service
    echo "================================================="
    
    if [ "$WARP_ENABLE" = true ]; then
        echo "正在测试 WARP 出口公网 IP (请稍候)..."
        sleep 3
        
        REAL_WARP_IP=$(curl -s --connect-timeout 5 -x socks5h://127.0.0.1:40000 https://ipv4.icanhazip.com)
        
        if [[ "$REAL_WARP_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo -e "WARP 兜底与防溯源状态: \033[32m全面生效 (公网出口 IP: $REAL_WARP_IP)\033[0m"
        else
            echo -e "WARP 兜底与防溯源状态: \033[31m失败或超时，请检查密钥是否有效\033[0m"
        fi
        echo "================================================="
    fi
    
    echo "节点分享链接已隐蔽保存至: /etc/xHTTP/clients.txt"
    echo "如需复制节点，请执行: cat /etc/xHTTP/clients.txt"
    echo "================================================="
    
    echo -e "\033[31m【极度重要】\033[0m"
    if [ "$START_PORT" -eq "$END_PORT" ]; then
        echo -e "请务必在 VPS 控制台（安全组）和系统防火墙中放行端口: \033[33m$START_PORT\033[0m"
    else
        echo -e "请务必在 VPS 控制台（安全组）和系统防火墙中放行端口: \033[33m$START_PORT - $END_PORT\033[0m"
    fi
    echo "================================================="
    echo ""
}

main() {
    [ -x /usr/local/bin/xHTTP ] || install_xHTTP
    config_xHTTP
}

main "$@"
