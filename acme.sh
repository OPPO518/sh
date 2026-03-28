#!/bin/bash

# 颜色定义，让交互界面更友好
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

# 1. 检查 root 权限
[[ $EUID -ne 0 ]] && echo -e "${red}错误：请以 root 用户运行此脚本！${plain}" && exit 1

clear
echo -e "${green}==================================================${plain}"
echo -e "${green}   多域名证书一键申请与自动分发脚本 (CF API 模式)${plain}"
echo -e "${green}   支持核心热重载: Xray, Sing-box, Hysteria2${plain}"
echo -e "${green}==================================================${plain}"

# 2. 交互式获取参数
read -p "$(echo -e "${yellow}请输入 Cloudflare API Token: ${plain}")" CF_TOKEN
if [[ -z "$CF_TOKEN" ]]; then
    echo -e "${red}API Token 不能为空！退出脚本。${plain}"
    exit 1
fi

read -p "$(echo -e "${yellow}请输入需要申请证书的域名 (多个域名请用空格隔开，例如: x.com y.com): ${plain}")" DOMAIN_INPUT
if [[ -z "$DOMAIN_INPUT" ]]; then
    echo -e "${red}域名不能为空！退出脚本。${plain}"
    exit 1
fi

# 将输入的字符串转换为数组
read -a DOMAIN_LIST <<< "$DOMAIN_INPUT"

# 统一定义节点证书的根目录绝对路径
BASE_CERT_DIR="/etc/ssl/node_certs"

# 3. 基础环境与 acme.sh 安装检查
echo -e "\n${green}---> 正在检查并补充基础系统依赖...${plain}"
if [ -x "$(command -v apt-get)" ]; then
    apt-get update -y >/dev/null 2>&1
    apt-get install -y curl cron socat >/dev/null 2>&1
    systemctl enable cron >/dev/null 2>&1
    systemctl start cron >/dev/null 2>&1
elif [ -x "$(command -v yum)" ]; then
    yum install -y curl cronie socat >/dev/null 2>&1
    systemctl enable crond >/dev/null 2>&1
    systemctl start crond >/dev/null 2>&1
fi

if [ ! -f ~/.acme.sh/acme.sh ]; then
    echo -e "${green}---> 未检测到 acme.sh，正在自动安装并配置默认 CA...${plain}"
    curl -s https://get.acme.sh | sh -s email="admin@${DOMAIN_LIST[0]}" >/dev/null 2>&1
    # 强制切换 Let's Encrypt，保证稳定性
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
    # 开启 acme.sh 自身代码的自动更新
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1
else
    echo -e "${green}---> acme.sh 已安装，跳过。${plain}"
fi

# 导出 Cloudflare Token 供 acme.sh 读取
export CF_Token="$CF_TOKEN"

# 4. 遍历域名，独立申请与部署
for DOMAIN in "${DOMAIN_LIST[@]}"; do
    echo -e "\n${yellow}==================================================${plain}"
    echo -e "${green}开始处理域名: ${DOMAIN}${plain}"
    echo -e "${yellow}==================================================${plain}"
    
    # 为当前域名创建专属绝对路径
    DOMAIN_CERT_DIR="${BASE_CERT_DIR}/${DOMAIN}"
    mkdir -p "$DOMAIN_CERT_DIR"

    # 执行 DNS API 签发 (强制 ECC 证书)
    echo -e "正在向 Let's Encrypt 发起 API 验证，请耐心等待 (约需 1-2 分钟)..."
    ~/.acme.sh/acme.sh --issue --dns dns_cf -d "$DOMAIN" -k ec-256

    # 检查是否签发成功并提取证书
    if ~/.acme.sh/acme.sh --list | grep -q "$DOMAIN"; then
        echo -e "验证通过！正在部署到指定路径并绑定热重载..."
        
        # 核心联动重启命令：无视哪个核心未安装，只管重启存在的服务
        RELOAD_CMD="systemctl restart xray sing-box hysteria-server 2>/dev/null || true"
        
        # 将证书安装到指定目录，绑定 reloadcmd 确保未来自动续期时生效
        ~/.acme.sh/acme.sh --install-cert -d "$DOMAIN" --ecc \
            --key-file       "$DOMAIN_CERT_DIR/private.key" \
            --fullchain-file "$DOMAIN_CERT_DIR/cert.crt" \
            --reloadcmd      "$RELOAD_CMD" >/dev/null 2>&1
            
        echo -e "\n${green}🟢 $DOMAIN 证书部署成功！${plain}"
        echo -e "配置您的节点文件时，请直接复制以下绝对路径："
        echo -e "公钥 (cert): ${yellow}${DOMAIN_CERT_DIR}/cert.crt${plain}"
        echo -e "私钥 (key) : ${yellow}${DOMAIN_CERT_DIR}/private.key${plain}"
        echo -e "状态: ${green}已接管自动续期 (每60天自动更新并重启节点核心)${plain}"
    else
        echo -e "\n${red}🔴 $DOMAIN 证书申请失败！请检查 API Token 权限或域名是否在 Cloudflare 正常解析。${plain}"
    fi
done

echo -e "\n${green}==================================================${plain}"
echo -e "${green}所有域名证书处理任务已完成。${plain}"
echo -e "${green}==================================================${plain}"
