#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (C) 2026 chenxin527

"""
uBootEnter.py - 直接通过物理网卡发送 UBOOT:ABORT 以太网帧
不依赖IP地址，链路未连通也能发送（网卡驱动允许的情况下）

用法:
  python uBootEnter.py list             # 列出物理网卡
  python uBootEnter.py all              # 在所有物理网卡上启用探测
  python uBootEnter.py 0                # 指定单个网卡（索引）进行探测
  python uBootEnter.py "以太网"          # 指定单个网卡（名称匹配）进行探测

依赖:
  pip install scapy requests
  Windows 需要安装 Npcap: https://npcap.com/
"""

import sys
import re
import time
import socket
import threading
import webbrowser
import requests
from requests.exceptions import RequestException, ConnectionError, Timeout
from scapy.all import *

# ============ 配置 ============
TARGET_MAC = "ff:ff:ff:ff:ff:ff"
TARGET_IP = "255.255.255.255"
SOURCE_IP = "0.0.0.0"  # 未分配IP时使用
TARGET_PORT = 37541
REPLY_PORT = 37540
MAGIC_DATA = b"UBOOT:ABORT"
MAGIC_REPLY = b"UBOOT:ABORTED"
INTERVAL = 0.3  # 发送间隔（秒）

# 版本检测配置
VERSION_CHECK_URL = "/version"
VERSION_CHECK_TIMEOUT = 15  # 版本检测超时（秒）
VERSION_CHECK_INTERVAL = 0.5  # 版本检测间隔（秒）
VERSION_RESPONSE_PREFIX = "U-Boot"  # 版本响应前缀
HTTP_TIMEOUT = 2  # HTTP请求超时（秒）

# ============ 全局状态 ============
running = True
success = False
success_iface = None
received_reply_ip = None
received_event = threading.Event()  # 线程安全的事件标志


def is_physical_interface(iface):
    """
    判断接口是否为物理网卡
    过滤掉虚拟网卡、环回接口、隧道接口等
    """
    if not hasattr(iface, 'description') or not iface.description:
        return False

    desc = iface.description.lower()
    name = iface.name.lower() if hasattr(iface, 'name') else ""

    # 虚拟网卡关键词（不区分大小写）
    virtual_keywords = [
        'virtual', 'vpn', 'tunnel', 'loopback', '环回',
        'hyper-v', 'virtualbox', 'vmware', 'wsl',
        'bluetooth', 'wi-fi direct', 'microsoft wi-fi direct',
        'teredo', 'isatap', '6to4',
        'miniport', 'wan miniport',
        'pseudo', 'ndis', 'vethernet',
        'usb over ethernet',  # USB网络共享设备（可选过滤）
    ]

    for keyword in virtual_keywords:
        if keyword in desc or keyword in name:
            return False

    # 环回接口特征（WiFi 网卡被过滤掉了？）
    # if hasattr(iface, 'flags'):
    #     if iface.flags & 0x8:  # IFF_LOOPBACK
    #         return False

    # MAC地址检查（全0或无MAC的通常是虚拟接口）
    if hasattr(iface, 'mac'):
        mac = iface.mac.replace(':', '').replace('-', '').upper()
        if mac == '000000000000' or mac == '':
            return False

    return True


def get_physical_interfaces():
    """
    获取所有物理网卡接口
    返回: [(索引, 接口对象), ...]
    """
    physical = []
    for i, iface in enumerate(IFACES.data.values()):
        if is_physical_interface(iface):
            physical.append((i, iface))
    return physical


def list_physical_interfaces():
    """输出物理网卡列表"""
    physical = get_physical_interfaces()

    if not physical:
        print("未找到物理网卡!")
        print("\n所有接口:")
        for i, iface in enumerate(IFACES.data.values()):
            if hasattr(iface, 'description'):
                print(f"  [{i}] {iface.description}")
                print(f"       名称: {iface.name}")
                print(f"       MAC: {iface.mac if hasattr(iface, 'mac') else 'N/A'}")
        sys.exit(1)

    print(f"\n找到 {len(physical)} 个物理网卡:\n")
    print(f"{'索引':<6} {'名称':<30} {'MAC':<20} {'描述'}")
    print("-" * 90)

    for idx, iface in physical:
        mac = iface.mac if hasattr(iface, 'mac') else 'N/A'
        name = iface.name if hasattr(iface, 'name') else 'N/A'
        desc = iface.description if hasattr(iface, 'description') else 'N/A'

        # 截断过长的描述
        if len(desc) > 40:
            desc = desc[:37] + "..."
        if len(name) > 30:
            name = name[:27] + "..."

        print(f"[{idx:<4}] {name:<30} {mac:<20} {desc}")

    print()
    return physical


def resolve_interfaces(interface_arg=None):
    """
    解析接口参数
    - None 或 "all": 所有物理网卡
    - 数字: 按索引指定单个网卡
    - 字符串: 按名称匹配单个网卡
    返回: [(索引, 接口对象), ...]
    """
    physical = get_physical_interfaces()

    if not physical:
        print("错误: 未找到物理网卡!")
        sys.exit(1)

    # 模式1: 所有网卡
    if interface_arg is None or interface_arg.lower() in ('all', 'auto', ''):
        print(f"模式: 所有物理网卡 ({len(physical)} 个)")
        return physical

    # 模式2: 按索引
    try:
        index = int(interface_arg)
        for idx, iface in physical:
            if idx == index:
                print(f"模式: 单网卡 (索引 {idx})")
                return [(idx, iface)]
        print(f"错误: 索引 {index} 不在物理网卡列表中")
        print(f"可用索引: {[p[0] for p in physical]}")
        sys.exit(1)
    except ValueError:
        pass

    # 模式3: 按名称匹配
    search_term = interface_arg.lower()
    matched = []

    for idx, iface in physical:
        name = iface.name.lower() if hasattr(iface, 'name') else ''
        desc = iface.description.lower() if hasattr(iface, 'description') else ''

        if search_term in name or search_term in desc:
            matched.append((idx, iface))

    if len(matched) == 0:
        print(f"错误: 未找到匹配 '{interface_arg}' 的物理网卡")
        print(f"可用接口:")
        for idx, iface in physical:
            desc = iface.description if hasattr(iface, 'description') else 'N/A'
            print(f"  [{idx}] {desc}")
        sys.exit(1)

    if len(matched) > 1:
        print(f"警告: 匹配到多个接口: '{interface_arg}'")
        for idx, iface in matched:
            desc = iface.description if hasattr(iface, 'description') else 'N/A'
            print(f"  [{idx}] {desc}")
        print(f"将使用第一个匹配项")
        matched = [matched[0]]

    print(f"模式: 单网卡 ({matched[0][1].name if hasattr(matched[0][1], 'name') else 'N/A'})")
    return matched


def send_uboot_packet(iface, src_mac=None):
    """
    通过指定接口发送 UBOOT:ABORT 数据包

    参数:
        iface: Scapy 接口对象
        src_mac: 源MAC地址 (None则自动获取)
    返回:
        bool: 发送是否成功
    """
    try:
        # 确定源MAC
        if src_mac is None:
            if hasattr(iface, 'mac') and iface.mac:
                src_mac = iface.mac
            else:
                # 使用随机本地MAC (保证不是多播/广播)
                src_mac = "02:00:00:00:00:01"

        # 构造数据包
        # 以太网层
        eth = Ether(dst=TARGET_MAC, src=src_mac)
        # IP层
        ip = IP(src=SOURCE_IP, dst=TARGET_IP, ttl=64, flags='DF')
        # UDP层
        udp = UDP(sport=40508, dport=TARGET_PORT)
        # 数据
        data = Raw(load=MAGIC_DATA)

        # 组装
        packet = eth / ip / udp / data

        # 删除校验和让Scapy重新计算
        del packet[IP].chksum
        del packet[UDP].chksum

        # 发送
        sendp(packet, iface=iface, verbose=False)
        return True
    except Exception as e:
        # 链路不通时可能失败，静默处理
        return False


# =====================================================================
# 可靠的接收方案：使用原始 socket + 循环轮询
# =====================================================================

def create_raw_listener():
    """
    创建一个原始 socket 监听 UDP 回复包。
    返回 socket 对象，如果创建失败返回 None。
    """
    try:
        # 尝试创建 UDP socket（在 Windows 上绑定到特定端口）
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.1)  # 100ms 超时，用于非阻塞循环

        try:
            # 尝试绑定到回复端口
            sock.bind(('0.0.0.0', REPLY_PORT))
        except OSError:
            # 端口可能被占用，绑定到随机端口也没关系，因为我们是广播接收
            sock.bind(('0.0.0.0', 0))

        return sock
    except Exception as e:
        print(f"[DEBUG] 创建UDP socket失败: {e}")
        return None


def create_sniff_listener(iface):
    """
    使用 Scapy AsyncSniffer 创建后台监听器。
    返回 AsyncSniffer 对象。
    """
    bpf_filter = f"udp and dst port {REPLY_PORT}"

    def process_packet(pkt):
        """收到包时的回调"""
        global success, received_reply_ip, received_event

        if success:
            return

        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            if payload == MAGIC_REPLY:
                # 尝试提取源IP
                src_ip = None
                if IP in pkt:
                    src_ip = pkt[IP].src

                print(f"\n[收到] UBOOT:ABORTED")
                if src_ip:
                    print(f"[收到] 来自: {src_ip}")
                    received_reply_ip = src_ip

                success = True
                received_event.set()

    sniffer = AsyncSniffer(
        iface=iface,
        filter=bpf_filter,
        prn=process_packet,
        store=False
    )
    return sniffer


def listen_with_raw_socket(timeout_seconds=2.0):
    """
    使用原始 UDP socket 轮询接收回复。

    返回: (bool, src_ip_string_or_None)
    """
    sock = create_raw_listener()
    if sock is None:
        return False, None

    start = time.time()

    while time.time() - start < timeout_seconds:
        try:
            data, addr = sock.recvfrom(2048)

            # addr = (ip_string, port)
            src_ip = addr[0]
            src_port = addr[1]

            # 检查是否是我们的回复包
            if data == MAGIC_REPLY:
                print(f"\n[收到] UBOOT:ABORTED 来自 {src_ip}:{src_port}")
                sock.close()
                return True, src_ip

            # 调试：打印其他收到的包
            # if len(data) > 0:
            #     print(f"[DEBUG] 收到其他包: {data[:50]} 来自 {addr}")

        except socket.timeout:
            # 超时正常，继续循环
            pass
        except OSError as e:
            if e.winerror == 10054:  # WSAECONNRESET
                # 端口不可达等，忽略
                pass

    sock.close()
    return False, None


def listen_for_reply(interfaces, timeout=1.0):
    """
    监听回复

    同时使用:
    1. AsyncSniffer 后台监听
    2. 原始 socket 轮询

    只要任一方法收到回复就返回 True。
    """
    global success, received_reply_ip, received_event

    success = False
    received_reply_ip = None
    received_event.clear()

    sniffer_list = []

    # 启动 AsyncSniffer 监听所有指定接口
    if interfaces:
        for _, iface in interfaces:
            try:
                sniffer = create_sniff_listener(iface)
                if sniffer is not None:
                    sniffer.start()
                    sniffer_list.append(sniffer)
            except Exception as e:
                print(f"[DEBUG] 无法在 {iface.name if hasattr(iface, 'name') else iface} 上启动监听: {e}")

    # 同时使用原始 socket 轮询
    start_time = time.time()

    while time.time() - start_time < timeout:
        # 检查 AsyncSniffer 是否已收到
        if received_event.is_set():
            break

        # 原始 socket 轮询（快速检查）
        rc, ip = listen_with_raw_socket(timeout_seconds=0.15)
        if rc:
            if received_reply_ip is None:
                received_reply_ip = ip
            received_event.set()
            break

    # 停止所有 sniffer
    for s in sniffer_list:
        try:
            s.stop()
        except:
            pass

    return received_event.is_set(), received_reply_ip


# =====================================================================
# 发送循环
# =====================================================================

def sender_single_interface(idx, iface):
    """单网卡模式"""
    global running

    count = 0
    start_time = time.time()

    while running:
        count += 1
        elapsed = time.time() - start_time

        result = send_uboot_packet(iface)

        if result:
            print(f"\r[{count}, {elapsed:.1f}s] ↑ 发送成功，监听中...", end="", flush=True)
        else:
            print(f"\r[{count}, {elapsed:.1f}s] × 发送失败", end="", flush=True)

        # 发送后立即检查回复
        received, src_ip = listen_for_reply([(idx, iface)], timeout=0.6)
        if received:
            global received_reply_ip
            if received_reply_ip is None:
                received_reply_ip = src_ip
            return count, elapsed, True

        # 等待后重试
        time.sleep(INTERVAL)

    return count, elapsed, False


def sender_all_interfaces(interfaces):
    """
    多网卡模式：向所有物理网卡发送
    """
    global running

    count = 0
    start_time = time.time()

    while running:
        count += 1
        elapsed = time.time() - start_time

        # 向所有接口发送
        send_results = []
        for _, iface in interfaces:
            result = send_uboot_packet(iface)
            send_results.append(result)

        success_count = sum(send_results)

        # 显示状态
        status_chars = ''.join(['↑' if r else '×' for r in send_results])
        print(f"\r[{count}, {elapsed:.1f}s] {status_chars} 监听中...", end="", flush=True)

        if success_count > 0:
            # 在所有有发送成功的接口上检查回复
            active_ifaces = [(idx, iface) for (idx, iface), ok in zip(interfaces, send_results) if ok]
            received, src_ip = listen_for_reply(active_ifaces, timeout=0.8)
            if received:
                global received_reply_ip
                if received_reply_ip is None:
                    received_reply_ip = src_ip
                return count, elapsed, True

        time.sleep(INTERVAL)

    return count, elapsed, False


# =====================================================================
# 版本检测和浏览器打开
# =====================================================================

def check_uboot_ready(ip_address):
    """
    检查 U-Boot Web 后台是否就绪
    通过访问 http://{ip}/version 检查返回值

    返回: (is_ready, version_string)
    """
    url = f"http://{ip_address}{VERSION_CHECK_URL}"

    try:
        response = requests.get(
            url,
            timeout=HTTP_TIMEOUT,
            headers={'User-Agent': 'uBootEnter/1.0'}
        )

        if response.status_code == 200:
            version_text = response.text.strip()

            # 检查是否以 "U-Boot" 开头
            if version_text.startswith(VERSION_RESPONSE_PREFIX):
                return True, version_text
            else:
                print(f"\n[检测] 版本格式不正确: {version_text[:50]}...")
                return False, version_text
        else:
            print(f"\n[检测] HTTP状态码: {response.status_code}")
            return False, None

    except ConnectionError:
        # 连接失败，HTTP服务可能还没启动
        return False, None
    except Timeout:
        # 超时
        return False, None
    except RequestException as e:
        # 其他网络错误
        print(f"\n[检测] 请求异常: {e}")
        return False, None


def wait_for_uboot_ready(ip_address):
    """
    循环检测 U-Boot 后台是否就绪

    返回: (is_ready, version_string)
    """
    print(f"\n{'='*60}")
    print(f"  等待 U-Boot Web 后台就绪...")
    print(f"  检测 URL: http://{ip_address}{VERSION_CHECK_URL}")
    print(f"  超时: {VERSION_CHECK_TIMEOUT}秒")
    print(f"{'='*60}\n")

    start_time = time.time()
    last_status_time = 0

    while time.time() - start_time < VERSION_CHECK_TIMEOUT:
        elapsed = time.time() - start_time
        remaining = VERSION_CHECK_TIMEOUT - elapsed

        # 每2秒显示一次状态
        if time.time() - last_status_time > 2.0:
            print(f"[{elapsed:.0f}s/{VERSION_CHECK_TIMEOUT}s] 正在检测... (剩余 {remaining:.0f}s)", end="\r", flush=True)
            last_status_time = time.time()

        is_ready, version_text = check_uboot_ready(ip_address)

        if is_ready:
            print(f"\n[✓] U-Boot 后台就绪!")
            print(f"[✓] 版本: {version_text}")
            return True, version_text

        # 等待后重试
        time.sleep(VERSION_CHECK_INTERVAL)

    print(f"\n[✗] 超时! U-Boot 后台未能在 {VERSION_CHECK_TIMEOUT}秒 内就绪")
    return False, None


def open_browser(url):
    """打开浏览器"""
    try:
        print(f"\n正在打开浏览器: {url}")
        time.sleep(0.3)
        webbrowser.open(url, new=2)
        print("浏览器已打开")
    except Exception as e:
        print(f"打开浏览器失败: {e}")
        print(f"请手动访问: {url}")


# =====================================================================
# 主程序
# =====================================================================

def main():
    global running, received_reply_ip

    # 解析命令行参数
    if len(sys.argv) > 1:
        arg = sys.argv[1]
        if arg.lower() in ('list', '-l', '--list'):
            list_physical_interfaces()
            return
        interface_arg = arg
    else:
        interface_arg = None

    # 解析接口
    interfaces = resolve_interfaces(interface_arg)

    # 显示信息
    print(f"\n{'='*60}")
    print(f"  U-Boot Network Abort Tool")
    print(f"{'='*60}")
    print(f"  目标: {TARGET_MAC}:{TARGET_PORT}")
    print(f"  回复端口: {REPLY_PORT}")
    print(f"  预期回复: {MAGIC_REPLY.decode()}")
    print(f"  发送间隔: {INTERVAL}秒")
    print(f"  监听方式: AsyncSniffer + Raw Socket")
    print(f"  版本检测: http://<uboot-ip>{VERSION_CHECK_URL}")
    print(f"  检测超时: {VERSION_CHECK_TIMEOUT}秒")

    if len(interfaces) > 1:
        print(f"  模式: 多网卡 ({len(interfaces)} 个)")
        for idx, iface in interfaces:
            desc = iface.description if hasattr(iface, 'description') else 'N/A'
            print(f"    [{idx}] {desc}")
    else:
        idx, iface = interfaces[0]
        desc = iface.description if hasattr(iface, 'description') else 'N/A'
        print(f"  模式: 单网卡")
        print(f"  接口: {desc}")

    print(f"{'='*60}")
    print(f"\n按 Ctrl+C 停止...\n")

    try:
        阶段1: 发送中断包并等待确认
        if len(interfaces) > 1:
            count, elapsed, success = sender_all_interfaces(interfaces)
        else:
            idx, iface = interfaces[0]
            count, elapsed, success = sender_single_interface(idx, iface)

        print()

        if success and received_reply_ip:
            print(f"\n{'='*60}")
            print(f"  ✓ 收到 UBOOT:ABORTED 确认!")
            print(f"  尝试次数: {count}")
            print(f"  耗时: {elapsed:.1f} 秒")
            print(f"  U-Boot IP: {received_reply_ip}")
            print(f"{'='*60}")

            # 阶段2: 等待 U-Boot 后台就绪
            is_ready, version_text = wait_for_uboot_ready(received_reply_ip)

            if is_ready:
                web_url = f"http://{received_reply_ip}"

                print(f"\n{'='*60}")
                print(f"  ✓ 系统就绪!")
                print(f"  U-Boot 版本: {version_text}")
                print(f"  Web 后台: {web_url}")
                print(f"{'='*60}")

                # 打开浏览器
                open_browser(web_url)
            else:
                print(f"\n{'='*60}")
                print(f"  ✗ U-Boot 后台未能在规定时间内就绪")
                print(f"  IP: {received_reply_ip}")
                print(f"  请手动检查或稍后访问: http://{received_reply_ip}")
                print(f"{'='*60}")
        else:
            print(f"\n已停止 (尝试 {count} 次, 耗时 {elapsed:.1f}秒)")

    except KeyboardInterrupt:
        print(f"\n\n用户中断")
    finally:
        running = False


if __name__ == "__main__":
    main()
