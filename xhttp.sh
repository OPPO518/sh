#!/bin/bash

DEFAULT_START_PORT=55000
IP_ADDRESSES=($(hostname -I))

install_xray() {
    echo "安装最新 Xray..."
    apt-get install -y curl unzip openssl || yum install -y curl unzip openssl
    LATEST_URL=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest \
        | grep browser_download_url | grep linux-64.zip | cut -d '"' -f 4)
    curl -L -o xray.zip "$LATEST_URL"
    unzip xray.zip
    mv xray /usr/local/bin/xrayL
    chmod +x /usr/local/bin/xrayL

    cat <<EOF >/etc/systemd/system/xrayL.service
[Unit]
Description=XrayL Service
After=network.target

[Service]
ExecStart=/usr/local/bin/xrayL -c /etc/xrayL/config.toml
Restart=on-failure
User=nobody
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable xrayL.service
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
    key_output=$(/usr/local/bin/xrayL x25519)
    PRIVATE_KEY=$(echo "$key_output" | grep Private | awk '{print $3}')
    PUBLIC_KEY=$(echo "$key_output" | grep Public | awk '{print $3}')
}

interactive_params() {

    # 伪装站点
    read -p "是否自定义伪装站点？(y/n) 默认: www.cloudflare.com: " custom_dest
    if [[ "$custom_dest" == "y" ]]; then
        read -p "请输入伪装站点（例如 www.cloudflare.com）: " REALITY_TARGET
    else
        REALITY_TARGET="www.cloudflare.com"
    fi

    # UUID
    read -p "是否自定义 UUID？(y/n) 默认自动生成: " custom_uuid
    if [[ "$custom_uuid" == "y" ]]; then
        read -p "请输入 UUID: " CUSTOM_UUID
    else
        CUSTOM_UUID=""
    fi

    # Reality 密钥对
    read -p "是否自定义 Reality 公钥/私钥？(y/n) 默认自动生成: " custom_key
    if [[ "$custom_key" == "y" ]]; then
        read -p "请输入 Reality 私钥: " PRIVATE_KEY
        read -p "请输入 Reality 公钥: " PUBLIC_KEY
    else
        generate_reality_keys
    fi

    # shortId
    read -p "是否自定义 shortId？(y/n) 默认自动生成 16 hex: " custom_sid
    if [[ "$custom_sid" == "y" ]]; then
        read -p "请输入 shortId（8-16 hex）: " SHORT_ID
    else
        SHORT_ID=$(openssl rand -hex 8)
    fi

    # XHTTP path
    read -p "是否自定义 XHTTP path？(y/n) 默认自动生成: " custom_path
    if [[ "$custom_path" == "y" ]]; then
        read -p "请输入 XHTTP path（例如 /abc123）: " XHTTP_PATH
    else
        XHTTP_PATH="/Client_upload_$(openssl rand -hex 4)"
    fi

    # 起始端口
    read -p "是否自定义起始端口？(y/n) 默认: $DEFAULT_START_PORT: " custom_port
    if [[ "$custom_port" == "y" ]]; then
        read -p "请输入起始端口: " START_PORT
    else
        START_PORT=$DEFAULT_START_PORT
    fi
}

config_xray() {
    mkdir -p /etc/xrayL
    filter_valid_ips
    interactive_params

    config_content=""
    index=0

    echo "" > /etc/xrayL/clients.txt

    for ip in "${IP_ADDRESSES[@]}"; do
        port=$((START_PORT + index))
        tag="tag_$((index+1))"

        # UUID
        if [[ -z "$CUSTOM_UUID" ]]; then
            uuid=$(cat /proc/sys/kernel/random/uuid)
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

        # 客户端配置写入
        echo "IP: $ip" >> /etc/xrayL/clients.txt
        echo "端口: $port" >> /etc/xrayL/clients.txt
        echo "UUID: $uuid" >> /etc/xrayL/clients.txt
        echo "Reality 公钥: $PUBLIC_KEY" >> /etc/xrayL/clients.txt
        echo "伪装站点: $REALITY_TARGET" >> /etc/xrayL/clients.txt
        echo "ShortID: $SHORT_ID" >> /etc/xrayL/clients.txt
        echo "XHTTP Path: $XHTTP_PATH" >> /etc/xrayL/clients.txt
        echo "" >> /etc/xrayL/clients.txt

        index=$((index+1))
    done

    echo -e "$config_content" >/etc/xrayL/config.toml
    systemctl restart xrayL.service
    systemctl --no-pager status xrayL.service

    echo ""
    echo "Reality + XHTTP 配置生成完成"
    echo "客户端配置已写入: /etc/xrayL/clients.txt"
    echo ""
}

main() {
    [ -x /usr/local/bin/xrayL ] || install_xray
    config_xray
}

main "$@"
