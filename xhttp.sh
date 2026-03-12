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
# 新版 Reality 密钥解析（PrivateKey / Password）
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
    interactive_params

    config_content="[routing]
domainStrategy = \"IPIfNonMatch\"

"
    index=0
    v2rayn_links=""

    # 提取第一个 IP 作为主入口 IP
    MAIN_IP="${IP_ADDRESSES[0]}"
    if [[ "$MAIN_IP" == *:* ]]; then
        CONN_IP="[$MAIN_IP]"
    else
        CONN_IP="$MAIN_IP"
    fi

    for ip in "${IP_ADDRESSES[@]}"; do
        port=$((START_PORT + index))
        tag="tag_$((index+1))"
        uuid="$GLOBAL_UUID"

        config_content+="[[inbounds]]
port = $port
protocol = \"vless\"
tag = \"$tag\"

[inbounds.settings]
decryption = \"none\"

[[inbounds.settings.clients]]
id = \"$uuid\"

[inbounds.streamSettings]
network = \"xhttp\"
security = \"reality\"

[inbounds.streamSettings.xhttpSettings]
path = \"$XHTTP_PATH\"

[inbounds.streamSettings.realitySettings]
show = false
dest = \"$REALITY_TARGET:443\"
serverNames = [\"$REALITY_TARGET\"]
privateKey = \"$PRIVATE_KEY\"
shortIds = [\"$SHORT_ID\"]

[[outbounds]]
sendThrough = \"$ip\"
protocol = \"freedom\"
tag = \"$tag\"

[[routing.rules]]
type = \"field\"
inboundTag = [\"$tag\"]
outboundTag = \"$tag\"

"

        spx_enc=$(echo -n "$XHTTP_PATH" | sed 's/\//%2F/g')
        # 所有链接统一使用 CONN_IP 作为连接地址，仅通过端口和别名区分
        v2rayn_link="vless://$uuid@$CONN_IP:$port?encryption=none&flow=&type=xhttp&security=reality&pbk=$PUBLIC_KEY&sid=$SHORT_ID&fp=chrome&path=$spx_enc&sni=$REALITY_TARGET#xHTTP-$ip"
        v2rayn_links+="$v2rayn_link\n"

        index=$((index+1))
    done

    END_PORT=$((START_PORT + index - 1))

    # 生成最终的整合日志
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

    echo -e "$config_content" >/etc/xHTTP/config.toml
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
