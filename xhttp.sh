#!/bin/bash

DEFAULT_START_PORT=20000
IP_ADDRESSES=($(hostname -I))

ask_yn() {
    local prompt="$1"
    local answer
    while true; do
        read -p "$prompt (y/n): " answer
        case "$answer" in
            y|Y) echo "y"; return ;;
            n|N) echo "n"; return ;;
            *) echo "请输入 y 或 n." ;;
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

    if [[ ! -f "xray.zip" ]]; then
        echo "下载失败，未找到 xray.zip"
        exit 1
    fi

    unzip xray.zip
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
        if [[ $ip =~ ^127\. ]] || [[ $ip =~ ^10\. ]] || [[ $ip =~ ^172\.16 ]] || [[ $ip =~ ^192\.168 ]]; then
            continue
        fi
        valid_ips+=("$ip")
    done
    IP_ADDRESSES=("${valid_ips[@]}")
}

generate_reality_keys() {
    echo "生成 Reality 密钥..."
    key_output=$(/usr/local/bin/xHTTP x25519)
    PRIVATE_KEY=$(echo "$key_output" | grep Private | awk '{print $3}')
    PUBLIC_KEY=$(echo "$key_output" | grep Public | awk '{print $3}')
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
            read -p "请输入 UUID: " CUSTOM_UUID
            [[ -n "$CUSTOM_UUID" ]] && break
            echo "UUID 不能为空."
        done
    else
        CUSTOM_UUID=""
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

    config_content=""
    index=0

    echo "" > /etc/xHTTP/clients.txt

    for ip in "${IP_ADDRESSES[@]}"; do
        port=$((START_PORT + index))
        tag="tag_$((index+1))"

        if [[ -z "$CUSTOM_UUID" ]]; then
            uuid=$(/usr/local/bin/xHTTP uuid)
        else
            uuid="$CUSTOM_UUID"
        fi

        config_content+="
[[inbounds]]
port = $port
protocol = \"vless\"
tag = \"$tag\"

[inbounds.settings]
decryption = \"none\"

[[inbounds.settings.clients]]
id = \"$uuid\"

[inbounds.streamSettings]
network = \"xhttp\"

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
inboundTag = \"$tag\"
outboundTag = \"$tag\"
"

        # IPv6 需要加中括号
        if [[ "$ip" == *:* ]]; then
            host="[$ip]"
        else
            host="$ip"
        fi

        spx_enc=$(echo -n "$XHTTP_PATH" | sed 's/\//%2F/g')
        v2rayn_link="vless://$uuid@$host:$port?encryption=none&flow=&type=xhttp&security=reality&pbk=$PUBLIC_KEY&sid=$SHORT_ID&fp=chrome&spx=$spx_enc&serverName=$REALITY_TARGET#xHTTP-$ip"

        {
            echo "IP: $ip"
            echo "端口: $port"
            echo "UUID: $uuid"
            echo "Reality 公钥: $PUBLIC_KEY"
            echo "伪装站点: $REALITY_TARGET"
            echo "ShortID: $SHORT_ID"
            echo "XHTTP Path: $XHTTP_PATH"
            echo "v2rayN 链接:"
            echo "$v2rayn_link"
            echo ""
        } >> /etc/xHTTP/clients.txt

        index=$((index+1))
    done

    echo -e "$config_content" >/etc/xHTTP/config.toml
    systemctl restart xHTTP.service
    systemctl --no-pager status xHTTP.service

    echo ""
    echo "Reality + XHTTP 配置生成完成"
    echo "客户端配置已写入: /etc/xHTTP/clients.txt"
    echo ""
}

main() {
    [ -x /usr/local/bin/xHTTP ] || install_xHTTP
    config_xHTTP
}

main "$@"
