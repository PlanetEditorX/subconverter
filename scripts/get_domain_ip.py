import os
import re
import sys
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

def resolve_with_all_dns_servers(domain, dns_server_ips):
    """
    使用提供的每个 DNS 服务器独立查询域名，并返回所有找到的 A 记录 (IPv4 地址)。
    """
    all_found_ips = set() # 使用集合来自动处理重复的 IP 地址

    for dns_server_ip in dns_server_ips:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server_ip] # 每次只指定一个 DNS 服务器
        resolver.timeout = 5
        resolver.lifetime = 5

        try:
            print(f"尝试使用 DNS 服务器 {dns_server_ip} 查询 '{domain}'...")
            answers = resolver.resolve(domain, 'A')
            for rdata in answers:
                all_found_ips.add(str(rdata))
            print(f"从 {dns_server_ip} 找到了 IP: {[str(rdata) for rdata in answers]}")

        except dns.resolver.NoAnswer:
            print(f"域名 '{domain}' 在 DNS 服务器 '{dns_server_ip}' 上没有找到 A 记录。")
        except dns.resolver.NXDOMAIN:
            print(f"域名 '{domain}' 在 DNS 服务器 '{dns_server_ip}' 上不存在。")
        except dns.exception.Timeout:
            print(f"查询 '{domain}' 到 DNS 服务器 '{dns_server_ip}' 超时。")
        except Exception as e:
            print(f"使用 DNS 服务器 '{dns_server_ip}' 解析 '{domain}' 时发生未知错误: {e}")

    return list(all_found_ips) # 返回去重后的 IP 地址列表

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
            if is_valid_ip(domain):
                print(f"{domain} 为IP，无需解析。")
                ip_addresses.add(domain)
            else:
                ips = resolve_with_all_dns_servers(domain, ["8.8.8.8", "1.1.1.1", "223.5.5.5", "94.140.14.14"])
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

# 检查是否有外部参数传入
if len(sys.argv) > 1:
    FileName = sys.argv[1]
else:
    print("没有接收到外部参数。默认写入AirportIP.list")
    FileName = 'AirportIP.list'

match FileName:
    case 'AirportIP.list':
        content_describe = "订阅机场IP解析结果"
    case 'FreeAirportIP.list':
        content_describe = "免费机场IP解析结果"
    case _:
        content_describe = "机场IP解析结果"

# 将结果写入到 AirportIP.list 文件
with open(f'../custom/{FileName}', 'w', encoding='utf-8') as f:
    f.write("######################################\n")
    f.write(f"# 内容：{content_describe}\n")
    f.write("# 数量：{}\n".format(len(ip_list)-title_nums))
    f.write("# 更新: {}\n".format(beijing_now.strftime("%Y-%m-%d %H:%M:%S")))
    f.write("######################################\n")
    f.writelines(ip_list)
