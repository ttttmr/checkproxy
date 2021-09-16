from scapy.all import *
from scapy.layers.inet import TCP, IP
import re
import hashlib
import base64
import os
import sys

lis_ip = sys.argv[1]
lis_port = sys.argv[2]

print(f"listening {lis_ip}:{lis_port}")


class TCPWindowZero(Sink):
    def __init__(self, lis_ip, lis_port):
        Sink.__init__(self)
        # k = ip:port , v = tcp packet
        self.tcp_conn = {}
        # k = ip:port , v = win 0 num
        self.win0_conn = {}
        self.lis_ip = str(lis_ip)
        self.lis_port = int(lis_port)

    # 检查数据是否处理
    def check(self, pkt):
        return (IP in pkt and pkt[IP].dst == self.lis_ip and
                TCP in pkt and pkt[TCP].dport == self.lis_port)

    def push(self, pkt):
        self.receive_data(pkt)

    def high_push(self, pkt):
        self.receive_data(pkt)

    def receive_data(self, pkt):
        if not self.check(pkt):
            return
        remote_addr = pkt[IP].src
        remote_port = pkt[TCP].sport
        remote_key = f"{remote_addr}:{remote_port}"
        if pkt[TCP].flags == "S":
            self.SYN(pkt, remote_key)
        elif pkt[TCP].flags == "A" and self.tcp_conn.get(remote_key, None):
            self.ACK(pkt, remote_key)
        elif pkt[TCP].flags == "PA" and self.tcp_conn.get(remote_key, None):
            self.PSH_ACK(pkt, remote_key)
        else:
            # 其他的数据包rst掉
            self.RST(pkt, remote_key)

    # SYN 尝试TCP握手
    def SYN(self, pkt, remote_key):
        ip = IP(src=self.lis_ip, dst=pkt[IP].src)
        synack = TCP(sport=self.lis_port, dport=pkt[TCP].sport,
                     flags="SA", seq=pkt[TCP].seq, ack=pkt[TCP].seq + 1)
        self.tcp_conn[remote_key] = synack
        send(ip / synack)

    # ACK 收ACK
    def ACK(self, pkt, remote_key):
        before_pkt = self.tcp_conn[remote_key]
        ip = IP(src=self.lis_ip, dst=pkt[IP].src)
        # 检查上一个回windowzero，响应probe ack
        if before_pkt.window == 0:
            if self.win0_conn.get(remote_key, 0) > 3:
                self.RST(pkt, remote_key)
            else:
                win0 = TCP(sport=self.lis_port, dport=pkt[TCP].sport, flags="A",
                           seq=pkt[TCP].ack, ack=pkt[TCP].seq, window=0)
                # self.tcp_conn[remote_key] = win0
                self.win0_conn[remote_key] = self.win0_conn.get(
                    remote_key, 0)+1
                send(ip / win0)
        # 拒绝keep-alive
        if pkt.seq + 1 == before_pkt.ack:
            self.RST(pkt, remote_key)

    # PSH_ACK 收数据
    def PSH_ACK(self, pkt, remote_key):
        before_pkt = self.tcp_conn[remote_key]
        # 有可能是websocket握手/websocket请求
        ip = IP(src=self.lis_ip, dst=pkt[IP].src)
        # 上一个包是syn+ack，做个psh+ack应该是websocket握手的http请求
        if before_pkt.flags == "SA":
            payload = ""
            try:
                payload = pkt[TCP].load.decode()
            except:
                # 可能decode失败，可能是tls握手
                # 目前发现 burp 在第一次连接的会尝试tls
                self.RST(pkt, remote_key)
                return
            m = key.search(payload)
            if m:
                skey = m.groups()[0].strip()
                skey = skey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                h = hashlib.sha1(skey.encode())
                rkey = base64.standard_b64encode(h.digest())
                html = "HTTP/1.1 101 Switching Protocols\x0d\x0aUpgrade: websocket\x0d\x0aConnection: Upgrade\x0d\x0aSec-WebSocket-Accept: " + rkey.decode() + \
                    "\x0d\x0a\x0d\x0a"
                ack = TCP(sport=self.lis_port, dport=pkt[TCP].sport,
                          flags="A", seq=pkt[TCP].seq, ack=pkt[TCP].ack + len(pkt[TCP].load))
                self.tcp_conn[remote_key] = ack
                send(ip / ack / html)
            else:
                # 没有匹配到，可能不是websocket握手，返回500，再rst
                html = "HTTP/1.1 500 Internal Server Error\x0d\x0aContent-Length: 0\x0d\x0a\x0d\x0a"
                ack = TCP(sport=self.lis_port, dport=pkt[TCP].sport,
                          flags="A", seq=pkt[TCP].seq, ack=pkt[TCP].ack + len(pkt[TCP].load))
                self.tcp_conn[remote_key] = ack
                send(ip / ack / html)
                return
        # 上一个包是ack，应该是建立了websocket连接，发送windowzero
        elif before_pkt.flags == "A":
            win0 = TCP(sport=self.lis_port, dport=pkt[TCP].sport, flags="A",
                       seq=pkt[TCP].ack, ack=pkt[TCP].seq + len(pkt[TCP].load), window=0)
            self.tcp_conn[remote_key] = win0
            send(ip / win0)
        else:
            self.RST(pkt, remote_key)
            return

    # 错误
    def RST(self, pkt, remote_key=None):
        if remote_key:
            self.tcp_conn.pop(remote_key)
        if IP in pkt and TCP in pkt:
            remote_addr = pkt[IP].src
            remote_port = pkt[TCP].sport
            os.system(
                f"iptables -A OUTPUT -p tcp --tcp-flags RST RST -d {remote_addr} --sport {remote_port} -j ACCEPT")
            ip = IP(src=self.lis_ip, dst=pkt[IP].src)
            rst = TCP(sport=self.lis_port, dport=pkt[TCP].sport, flags="R",
                      seq=pkt[TCP].ack, ack=0, window=0)
            send(ip / rst)
            os.system(
                f"iptables -D OUTPUT -p tcp --tcp-flags RST RST -d {remote_addr} --sport {remote_port} -j ACCEPT")


os.system(
    f"iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport {lis_port} -j DROP")

key = re.compile("Sec-WebSocket-Key: (.+)", re.IGNORECASE)

source = SniffSource(
    iface=conf.iface, filter=f"tcp and host {lis_ip} and port {lis_port}")

w = TCPWindowZero(lis_ip, lis_port)

source > w

p = PipeEngine(source)
p.start()
try:
    p.wait_and_stop()
except BaseException:
    os.system(
        f"iptables -D OUTPUT -p tcp --tcp-flags RST RST --sport {lis_port} -j DROP")
