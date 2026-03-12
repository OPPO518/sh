#!/bin/bash

DEFAULT_START_PORT=20000
IP_ADDRESSES=($(hostname -I))

############################################
# y/n 输入校验
############################################
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

############################################
# 参数校验函数
############################################
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

############################################
# 安装最新 Xray 并重命名为 xHTTP
############################################
install_xHTTP() {
    echo "安装最新 Xray（重命名为 xHTTP）..."
    apt-get install -y curl unzip openssl 2>/dev/null || yum install -y curl unzip openssl 2>/dev/null

    echo "获取最新版本号..."
    LATEST_TAG=$(curl -s https://github.com/XTLS/Xray-core/releases/latest \
        | grep -oP 'tag/\K[^"]+')

    if [[ -z "$LATEST_TAG" ]]; then
        echo "无法获取最新版本号，请检查网络或 GitHub 访问情况."
        exit 1
    fi

    LATEST_URL="https://github.com/XTLS/Xray-core/releases/download/$LATEST_TAG/Xray-linux-64.zip"

    echo "下载: $LATEST_URL"
    curl -L -o xray.zip "$LATEST_URL"

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

############################################
# 过滤无效 IP
############################################
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

############################################
# Reality 密钥生成
############################################
generate_reality_keys() {
    echo "生成 Reality 密钥..."
    key_output=$(/usr/local/bin/xHTTP x25519)
    PRIVATE_KEY=$(echo "$key_output" | grep Private | awk '{print $3}')
    PUBLIC_KEY=$(echo "$key_output" | grep Public | awk '{print $3}')
}

############################################
# 交互式参数
############################################
interactive_params() {

    # 伪装站点
    custom_dest=$(ask_yn "是否自定义伪装站点？默认: www.cloudflare.com")
    if [[ "$custom_dest" == "y" ]]; then
        while true; do
            read -p "请输入伪装站点（例如 www.cloudflare.com）: " REALITY_TARGET
            [[ -n "$REALITY_TARGET" ]] && break
            echo "伪装站点不能为空."
        done
    else
        REALITY_TARGET="www.cloudflare.com"
    fi

    # UUID：是否自定义，否则用 xHTTP uuid 自动生成
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

    # Reality 密钥对
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

    # shortId
    custom_sid=$(ask_yn "是否自定义 shortId？默认自动生成 16 hex")
    if [[ "$custom_sid" == "y" ]]; then
        while true; do
            read -p "请输入 shortId（8-16 hex）: " SHORT_ID
            validate_hex_len "$SHORT_ID" && break
            echo "shortId 必须为 8-16 位十六进制字符."
        done
    else
        SHORT_ID=$(openssl rand -hex 8)   # 16 hex
    fi

    # XHTTP path
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

    # 起始端口
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

############################################
# 生成配置
############################################
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

        # UUID：如果未自定义，则用 xHTTP uuid 生成
        if [[ -z "$CUSTOM_UUID" ]]; then
            uuid=$(/usr/local/bin/xHTTP uuid)
        else
            uuid="$CUSTOM_UUID"
        fi

        ############################################
        # 写入 Xray 配置
        ############################################
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

        ############################################
        # 生成 v2rayN 链接
        ############################################
        # spx 需要 URL 编码 / → %2F
        spx_enc=$(echo -n "$XHTTP_PATH" | sed 's/\//%2F/g')
        v2rayn_link="vless://$uuid@$ip:$port?encryption=none&flow=&type=xhttp&security=reality&pbk=$PUBLIC_KEY&sid=$SHORT_ID&fp=chrome&spx=$spx_enc&serverName=$REALITY_TARGET#xHTTP-$ip"

        ############################################
        # 写入 clients.txt
        ############################################
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

############################################
# 主程序
############################################
main() {
    [ -x /usr/local/bin/xHTTP ] || install_xHTTP
    config_xHTTP
}

main "$@"
