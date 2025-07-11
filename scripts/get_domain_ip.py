import os
import re
import glob
import pytz
import socket
import datetime
import ipaddress
import dns.resolver
import dns.exception

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def resolve_with_specific_dns(domain, dns_server_ips):
    """
    使用指定的 DNS 服务器解析域名并返回所有 A 记录 (IPv4 地址)。
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = dns_server_ips # 指定 DNS 服务器 IP 地址
    resolver.timeout = 5 # 设置查询超时时间 (秒)
    resolver.lifetime = 5 # 设置总查询生命周期 (秒)

    try:
        # 查询 A 记录 (IPv4 地址)
        answers = resolver.resolve(domain, 'A')
        ips = [str(rdata) for rdata in answers]
        return ips
    except dns.resolver.NoAnswer:
        print(f"域名 '{domain}' 在指定 DNS 服务器 '{dns_server_ips}' 上没有找到 A 记录。")
        return []
    except dns.resolver.NXDOMAIN:
        print(f"域名 '{domain}' 不存在。")
        if is_valid_ip(domain):
            print(f"'{domain}' 是一个有效的 IP 地址，但不是域名。")
            return [domain]
        return []
    except dns.exception.Timeout:
        print(f"查询 '{domain}' 到 DNS 服务器 '{dns_server_ips}' 超时。")
        return []
    except Exception as e:
        print(f"解析 '{domain}' 时发生未知错误: {e}")
        return []

def ip_to_tuple(ip):
    return tuple(int(part) for part in ip.split('.'))

def get_ips_from_domains(file_path):
    ip_addresses = set()
    domains = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # 尝试匹配常见的域名模式（可能需要根据你的订阅文件格式调整）
            # 这是一个通用的匹配，可能需要更精确的正则
            found_domains = re.findall(r'"server":"([^"]+)"', content)
            if not found_domains: # 如果没有找到，尝试其他常见格式
                found_domains = re.findall(r'server:\s*([^,\s]+)', content)
            for domain in found_domains:
                # 简单过滤一些非域名或内部地址
                if not domain.startswith(('10.', '172.', '192.', '127.', '-')) and '.' in domain:
                    domains.append(domain)

    except FileNotFoundError:
        print(f"错误：文件 '{file_path}' 未找到。")
        return

    print(f"在文件中找到 {len(domains)} 个潜在域名。开始解析...")

    for domain in sorted(list(set(domains))): # 去重并排序
        try:
            ips = resolve_with_specific_dns(domain, ["8.8.8.8", "1.1.1.1"])
            for ip in ips:
                ip_addresses.add(ip)
                print(f"解析 {domain} -> {ip}")
        except socket.gaierror:
            print(f"无法解析域名: {domain}")
        except Exception as e:
            print(f"解析 {domain} 时发生错误: {e}")

    return sorted(list(ip_addresses), key=ip_to_tuple)

ip_list = []
title_nums = 0
# 遍历当前目录下的所有 YAML 文件
for file_name in glob.glob('*.yaml'):
    print(f"正在处理文件: {file_name}")
    file_path = file_name
    ips = get_ips_from_domains(file_path)
    if ips:
        print(f"\n--- 解析到的 {file_name} 所有 IP 地址 ---")
        ip_list.append(f"\n# {file_name} 解析结果\n")
        for ip in ips:
            print(ip)
            ip_list.append(f"IP-CIDR,{ip}/32,no-resolve\n")
        title_nums += 1
    else:
        print(f"未找到任何 IP 地址。请检查文件 {file_name} 的内容和解析逻辑。")
print("\n--- 所有解析到的 IP 地址 ---")
for ip in ip_list:
    print(ip)
print("\n--- 解析完成 ---")

# 获取UTC时间
utc_now = datetime.datetime.now(pytz.utc)
# 转换为北京时间
beijing_tz = pytz.timezone('Asia/Shanghai')
beijing_now = utc_now.astimezone(beijing_tz)

# 将结果写入到 AirportIP.list 文件
with open('../custom/AirportIP.list', 'w', encoding='utf-8') as f:
    f.write("######################################\n")
    f.write("# 内容：机场IP解析结果\n")
    f.write("# 数量：{}\n".format(len(ip_list)-title_nums))
    f.write("# 更新: {}\n".format(beijing_now.strftime("%Y-%m-%d %H:%M:%S")))
    f.write("######################################\n")
    f.writelines(ip_list)
