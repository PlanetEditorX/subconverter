#!/bin/sh
# OpenClash Smart 一键修复脚本
# 适用：ImmortalWrt/OpenWrt + OpenClash + Mihomo Smart 核心
# 作用：保留 Smart/自动 Smart 切换，减少 DNS 半开连接，并增加每日自动恢复。

set -u
umask 077

log() {
    printf '%s\n' "$*"
}

die() {
    log "ERROR: $*"
    exit 1
}

[ "$(id -u)" = "0" ] || die "请使用 root 执行。"
[ -x /etc/init.d/openclash ] || die "未找到 OpenClash。"
[ -x /sbin/uci ] || die "未找到 UCI。"

RAW_CFG=$(uci -q get openclash.config.config_path 2>/dev/null || true)
[ -n "$RAW_CFG" ] || RAW_CFG=/etc/openclash/config/Overwrite-Clash-Bypass-Dialer.yaml
CFG_NAME=$(basename "$RAW_CFG")
ACTIVE_CFG=/etc/openclash/$CFG_NAME
PROFILE_NAME=${CFG_NAME%.*}
OVERWRITE_FILE=/etc/openclash/overwrite/$PROFILE_NAME
SUBSCRIPTION_UPDATE_INTERVAL=43200
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP=/root/openclash-backup-$STAMP

log "[1/6] 创建备份：$BACKUP"
mkdir -p "$BACKUP" || die "无法创建备份目录。"
cp -a /etc/config/openclash "$BACKUP/" || die "备份 UCI 配置失败。"
[ -f "$RAW_CFG" ] && cp -a "$RAW_CFG" "$BACKUP/"
[ -f "$ACTIVE_CFG" ] && cp -a "$ACTIVE_CFG" "$BACKUP/"
[ -f "$OVERWRITE_FILE" ] && cp -a "$OVERWRITE_FILE" "$BACKUP/"
[ -f /etc/openclash/history/$PROFILE_NAME.db ] && cp -a /etc/openclash/history/$PROFILE_NAME.db "$BACKUP/"
[ -f /etc/openclash/smart_weight_data.csv ] && cp -a /etc/openclash/smart_weight_data.csv "$BACKUP/"
[ -f /etc/openclash/Model.bin ] && cp -a /etc/openclash/Model.bin "$BACKUP/"

[ -f "$OVERWRITE_FILE" ] || die "未找到本地覆盖文件：$OVERWRITE_FILE"

set_overwrite_key() {
    key="$1"
    value="$2"
    if grep -qE "^${key}[[:space:]]*=" "$OVERWRITE_FILE"; then
        sed -i "s#^${key}[[:space:]]*=.*#${key} = ${value}#" "$OVERWRITE_FILE"
    else
        printf '%s = %s\n' "$key" "$value" >> "$OVERWRITE_FILE"
    fi
}

log "[2/6] 保留并确认 Smart 配置"
set_overwrite_key CORE_TYPE Smart
set_overwrite_key AUTO_SMART_SWITCH 1
set_overwrite_key SMART_ENABLE_LGBM 1
set_overwrite_key ENABLE_CUSTOM_DNS 1
set_overwrite_key APPEND_DEFAULT_DNS 1
set_overwrite_key APPEND_WAN_DNS 0

uci -q set openclash.config.smart_enable=1
uci -q set openclash.config.core_type=Smart
uci -q set openclash.config.auto_smart_switch=1
uci -q set openclash.config.smart_enable_lgbm=1
uci -q set openclash.config.auto_restart=1
uci -q set openclash.config.auto_restart_week_time='*'
uci -q set openclash.config.auto_restart_day_time=4

uci -q set openclash.@overwrite[0].core_type=Smart
uci -q set openclash.@overwrite[0].auto_smart_switch=1
uci -q set openclash.@overwrite[0].smart_enable_lgbm=1
uci -q set openclash.@overwrite[0].enable_custom_dns=1
uci -q set openclash.@overwrite[0].append_default_dns=1
uci -q set openclash.@overwrite[0].append_wan_dns=0

log "[2/6] 固化 EN_KEY 订阅刷新周期：每 12 小时"
if ! grep -q "proxy-providers.*interval" "$OVERWRITE_FILE"; then
    printf '%s\n' "ruby_edit \"\$CONFIG_FILE\" \"['proxy-providers']['Sub-store']['interval']\" \"$SUBSCRIPTION_UPDATE_INTERVAL\"" >> "$OVERWRITE_FILE"
fi

find_dns() {
    target_ip="$1"
    target_type="$2"
    target_group="$3"
    i=0
    while [ "$i" -lt 128 ]; do
        ip=$(uci -q get openclash.@dns_servers[$i].ip 2>/dev/null || true)
        type=$(uci -q get openclash.@dns_servers[$i].type 2>/dev/null || true)
        group=$(uci -q get openclash.@dns_servers[$i].group 2>/dev/null || true)
        if [ "$ip" = "$target_ip" ] && [ "$type" = "$target_type" ] && [ "$group" = "$target_group" ]; then
            printf '%s\n' "$i"
            return 0
        fi
        i=$((i + 1))
    done
    return 1
}

set_dns_enabled() {
    idx="$1"
    enabled="$2"
    [ -n "$idx" ] && uci -q set openclash.@dns_servers[$idx].enabled="$enabled"
}

log "[3/6] 收敛 DNS 上游，避免大量半开连接"
# nameserver 只保留国内 UDP DNS；禁用其它 nameserver 项。
i=0
while [ "$i" -lt 128 ]; do
    group=$(uci -q get openclash.@dns_servers[$i].group 2>/dev/null || true)
    [ "$group" = "nameserver" ] && set_dns_enabled "$i" 0
    i=$((i + 1))
done
set_dns_enabled "$(find_dns 114.114.114.114 udp nameserver || true)" 1
set_dns_enabled "$(find_dns 119.29.29.29 udp nameserver || true)" 1
set_dns_enabled "$(find_dns 223.5.5.5 udp nameserver || true)" 1

# fallback 只保留两个 UDP 上游，避免 DoH/TLS 反复建立 TCP 连接。
i=0
while [ "$i" -lt 128 ]; do
    group=$(uci -q get openclash.@dns_servers[$i].group 2>/dev/null || true)
    [ "$group" = "fallback" ] && set_dns_enabled "$i" 0
    i=$((i + 1))
done
set_dns_enabled "$(find_dns 9.9.9.9 udp fallback || true)" 1
set_dns_enabled "$(find_dns 149.112.112.112 udp fallback || true)" 1
uci -q commit openclash

log "[4/6] 强制重新生成配置并加入每日 04:00 自动重启"
# OpenClash 的 quick-start 会跳过配置生成；删除标记后重新生成。
rm -f /tmp/openclash.change
/etc/init.d/openclash restart >/dev/null 2>&1 || true
sleep 20

log "[5/6] 检查服务和 Smart 状态"
/etc/init.d/openclash status 2>/dev/null || true
pid=$(pidof clash 2>/dev/null || true)
[ -n "$pid" ] || die "Clash 核心未启动，请查看 /tmp/openclash.log。"

core_version=$(/etc/openclash/clash -v 2>/dev/null | head -n 1 || true)
smart_groups=$(grep -Ec '^  type: smart$' "$ACTIVE_CFG" 2>/dev/null || true)
provider_interval=$(awk '/^proxy-providers:/{p=1} p && /interval:/{print $2; exit}' "$ACTIVE_CFG" 2>/dev/null || true)
cron_ok=$(grep -c '0 4 \* \* \* /etc/init.d/openclash restart #openclash-cron-task' /etc/crontabs/root 2>/dev/null || true)

log "核心：$core_version"
log "Smart 策略组数量：$smart_groups"
log "订阅缓存刷新间隔：${provider_interval:-unknown} 秒"
log "每日自动重启：$cron_ok（1 表示已启用）"
log "备份目录：$BACKUP"

log "[6/6] 当前资源状态"
free 2>/dev/null || true
printf 'conntrack: '
cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null || printf 'unavailable\n'
printf 'socket states:\n'
netstat -ant 2>/dev/null | awk 'NR > 2 { count[$6]++ } END { for (state in count) print state, count[state] }' | sort

log "修复完成。Smart 核心和自动 Smart 切换均已保留。"
