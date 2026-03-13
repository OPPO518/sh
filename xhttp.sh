#!/bin/bash

DEFAULT_START_PORT=20000
IP_ADDRESSES=($(hostname -I))

ask_yn() {
    local prompt="$1"
    local answer
    while true; do
        read -p "$prompt (y/n): " answer >&2
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
# WARP API 自动注册提取 (用于 IPv6 的 IPv4 兜底)
############################################
generate_warp_keys() {
    echo "================================================="
    echo "检测到存在 IPv6 地址，正在自动注册 WARP 获取 IPv4 兜底密钥..."
    echo "================================================="
    
    if ! command -v wg &> /dev/null; then
        apt-get install -y wireguard-tools 2>/dev/null || yum install -y wireguard-tools 2>/dev/null
    fi
    if ! command -v xxd &> /dev/null; then
        apt-get install -y xxd 2>/dev/null || yum install -y vim-common 2>/dev/null
    fi

    WARP_PRIVATE_KEY=$(wg genkey)
    WARP_PUBLIC_KEY=$(echo "$WARP_PRIVATE_KEY" | wg pubkey)

    INSTALL_ID=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 22 | head -n 1)
    FCM_TOKEN="${INSTALL_ID}:APA91b"
    TOS=$(date -u +%Y-%m-%dT%H:%M:%S.000Z)

    RESPONSE=$(curl -s -A "okhttp/3.12.1" -H "CF-Client-Version: a-6.11-3306" \
        -X POST "https://api.cloudflareclient.com/v0a884/reg" \
        -d "{\"key\":\"$WARP_PUBLIC_KEY\",\"install_id\":\"$INSTALL_ID\",\"fcm_token\":\"$FCM_TOKEN\",\"tos\":\"$TOS\",\"model\":\"Linux\",\"build\":\"27.0\",\"locale\":\"en_US\"}")

    # 精确匹配 172. 开头的内网 IP，避免抓取到 endpoint 导致换行错误
    WARP_IPV4=$(echo "$RESPONSE" | grep -o '"v4":"[^"]*"' | awk -F'"' '{print $4}' | grep '^172\.' | head -n 1)
    
    # 终极兜底：如果 API 返回异常，强制给定标准内网 IP
    if [[ -z "$WARP_IPV4" ]]; then
        WARP_IPV4="172.16.0.2"
    fi

    CLIENT_ID=$(echo "$RESPONSE" | grep -o '"id":"[^"]*"' | awk -F'"' '{print $4}')

    if [[ -z "$CLIENT_ID" ]]; then
        echo "WARP 自动注册失败！IPv6 节点可能无法访问 IPv4 网站。"
        WARP_ENABLE=false
        return
    fi

    RESERVED_HEX=$(echo -n "${CLIENT_ID:0:4}" | base64 -d 2>/dev/null | xxd -p | head -c 6)
    R1=$((16#${RESERVED_HEX:0:2}))
    R2=$((16#${RESERVED_HEX:2:2}))
    R3=$((16#${RESERVED_HEX:4:2}))
    WARP_RESERVED="[$R1, $R2, $R3]"
    WARP_ENABLE=true
    
    echo "WARP 注册成功! 分配专属 IPv4: $WARP_IPV4"
    echo "Reserved 计算完毕: $WARP_RESERVED"
    echo "================================================="
}

############################################
# 新版 Reality 密钥解析
############################################
generate_reality_keys() {
    echo "生成 Reality 密钥..."
    key_output=$(/usr/local/bin/xHTTP x25519 2>/dev/null)

    PRIVATE_KEY=$(echo "$key_output" | grep -i 'PrivateKey' | awk -F': ' '{print $2}' | tr -d ' ')
    PUBLIC_KEY=$(echo "$key_output" | grep -i 'Password' | awk -F': ' '{print $2}' | tr -d ' ')

    if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
        echo "Reality 密钥解析失败，请检查 xHTTP x25519 输出格式"
        exit 1
    fi
}

interactive_params() {
    custom_dest=$(ask_yn "是否自定义伪装站点？默认: www.cloudflare.com")
    if [[ "$custom_dest" == "y" ]]; then
        while true; do
            read -p "请输入伪装站点（例如 swcdn.apple.com）: " REALITY_TARGET
            [[ -n "$REALITY_TARGET" ]] && break
            echo "伪装站点不能为空."
        done
    else
        REALITY_TARGET="www.cloudflare.com"
    fi

    custom_uuid=$(ask_yn "是否自定义 UUID？默认使用 xHTTP uuid 自动生成")
    if [[ "$custom_uuid" == "y" ]]; then
        while true; do
            read -p "请输入 UUID: " GLOBAL_UUID
            [[ -n "$GLOBAL_UUID" ]] && break
            echo "UUID 不能为空."
        done
    else
        GLOBAL_UUID=$(/usr/local/bin/xHTTP uuid)
    fi

    custom_key=$(ask_yn "是否自定义 Reality 公钥/私钥？默认自动生成")
    if [[ "$custom_key" == "y" ]]; then
        while true; do
            read -p "请输入 Reality 私钥: " PRIVATE_KEY
            read -p "请输入 Reality 公钥: " PUBLIC_KEY
            [[ -n "$PRIVATE_KEY" && -n "$PUBLIC_KEY" ]] && break
            echo "公钥和私钥不能为空."
        done
    else
        generate_reality_keys
    fi

    custom_sid=$(ask_yn "是否自定义 shortId？默认自动生成 16 hex")
    if [[ "$custom_sid" == "y" ]]; then
        while true; do
            read -p "请输入 shortId（8-16 hex）: " SHORT_ID
            validate_hex_len "$SHORT_ID" && break
            echo "shortId 必须为 8-16 位十六进制字符."
        done
    else
        SHORT_ID=$(openssl rand -hex 8)
    fi

    custom_path=$(ask_yn "是否自定义 XHTTP path？默认自动生成")
    if [[ "$custom_path" == "y" ]]; then
        while true; do
            read -p "请输入 XHTTP path（例如 /abc123）: " XHTTP_PATH
            validate_path "$XHTTP_PATH" && break
            echo "path 必须以 / 开头且不包含空白字符."
        done
    else
        XHTTP_PATH="/Client_upload_$(openssl rand -hex 4)"
    fi

    custom_port=$(ask_yn "是否自定义起始端口？默认: $DEFAULT_START_PORT")
    if [[ "$custom_port" == "y" ]]; then
        while true; do
            read -p "请输入起始端口: " START_PORT
            validate_port "$START_PORT" && break
            echo "端口必须为 1-65535."
        done
    else
        START_PORT=$DEFAULT_START_PORT
    fi
}

config_xHTTP() {
    mkdir -p /etc/xHTTP
    filter_valid_ips
    
    WARP_ENABLE=false
    for ip in "${IP_ADDRESSES[@]}"; do
        if [[ "$ip" == *":"* ]]; then
            generate_warp_keys
            break
        fi
    done

    interactive_params

    config_content="[routing]
domainStrategy = \"IPIfNonMatch\"

"
    inbounds_section=""
    outbounds_section=""
    routing_section=""

    if [ "$WARP_ENABLE" = true ]; then
        outbounds_section+="[[outbounds]]
tag = \"warp-ipv4\"
protocol = \"wireguard\"

[outbounds.settings]
mtu = 1420
secretKey = \"$WARP_PRIVATE_KEY\"
address = [\"$WARP_IPV4/32\"]
workers = 2
domainStrategy = \"ForceIPv4\"
reserved = $WARP_RESERVED
noKernelTun = true

[[outbounds.settings.peers]]
publicKey = \"bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=\"
allowedIPs = [\"0.0.0.0/0\"]
endpoint = \"[2606:4700:d0::a29f:c001]:2408\"
keepAlive = 0

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

"
        if [[ "$ip" == *":"* ]] && [ "$WARP_ENABLE" = true ]; then
            routing_section+="[[routing.rules]]
type = \"field\"
inboundTag = [\"$in_tag\"]
ip = [\"0.0.0.0/0\"]
outboundTag = \"warp-ipv4\"

[[routing.rules]]
type = \"field\"
inboundTag = [\"$in_tag\"]
ip = [\"[::]/0\"]
outboundTag = \"$out_tag\"

"
        else
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
    systemctl --no-pager status xHTTP.service

    echo ""
    echo "================================================="
    echo "        Reality + XHTTP 配置生成完成             "
    echo "================================================="
    cat /etc/xHTTP/clients.txt
    echo "================================================="
    echo "客户端配置已保存至: /etc/xHTTP/clients.txt"
    echo ""
}

main() {
    [ -x /usr/local/bin/xHTTP ] || install_xHTTP
    config_xHTTP
}

main "$@"
