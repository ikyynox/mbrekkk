import socket, struct, os, sys
H = os.environ.get('FP_HOST', 'resi.fastproxy.to'); P = int(os.environ.get('FP_PORT', '9696'))
user = input('Username (pakai session tetap, mis. ...-session-udp0001-time-long): ').strip()
pw = input('Password: ').strip()
q = bytes.fromhex('123401000001000000000000076578616d706c6503636f6d0000010001')
KODE = {0: 'sukses', 1: 'general SOCKS server failure', 2: 'dilarang aturan', 3: 'network unreachable', 4: 'host unreachable', 5: 'connection refused', 7: 'command not supported', 8: 'address type not supported'}

def konek():
    s = socket.create_connection((H, P), timeout=15)
    s.sendall(b'\x05\x01\x02')
    r = s.recv(2)
    if len(r) < 2 or r[1] != 2: print('Server tidak minta user/pass, balasan:', r); sys.exit(1)
    u, p = user.encode(), pw.encode()
    s.sendall(b'\x01' + bytes([len(u)]) + u + bytes([len(p)]) + p)
    a = s.recv(2)
    if len(a) < 2 or a[1] != 0: print('LOGIN DITOLAK:', a); sys.exit(1)
    return s

def associate(s, ip, port):
    s.sendall(b'\x05\x03\x00\x01' + socket.inet_aton(ip) + struct.pack('>H', port))
    return s.recv(262)

print('1) Login SOCKS5 ...'); konek().close(); print('   OK')

# Varian A: alamat 0.0.0.0 port 0 (standar RFC 1928)
# Varian B: alamat asli VPS + port UDP lokal yang sudah dibuka (sebagian server meminta ini)
hasil = None
for nama in ('A (0.0.0.0:0)', 'B (IP VPS + port lokal)'):
    s = konek()
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); us.bind(('0.0.0.0', 0)); us.settimeout(8)
    if nama.startswith('A'): rep = associate(s, '0.0.0.0', 0)
    else:
        lip = s.getsockname()[0]; rep = associate(s, lip, us.getsockname()[1])
    kode = rep[1] if len(rep) > 1 else None
    print('2) UDP ASSOCIATE varian %s -> kode %s (%s)' % (nama, kode, KODE.get(kode, '?')))
    if kode == 0 and len(rep) >= 10 and rep[3] == 1:
        baddr = socket.inet_ntoa(rep[4:8]); bport = struct.unpack('>H', rep[8:10])[0]
        relay = baddr if baddr != '0.0.0.0' else socket.gethostbyname(H)
        print('   relay =', relay, 'port', bport, '| IP proxy untuk tunnel =', socket.gethostbyname(H))
        us.sendto(b'\x00\x00\x00\x01' + socket.inet_aton('1.1.1.1') + struct.pack('>H', 53) + q, (relay, bport))
        try:
            d, src = us.recvfrom(2048)
            print('3) Balasan DNS lewat UDP relay: OK (%d byte dari %s)' % (len(d), src[0])); hasil = True
        except socket.timeout:
            print('3) Tidak ada balasan UDP dalam 8 detik')
        break
    s.close(); us.close()
if hasil is None: print('KESIMPULAN: UDP ASSOCIATE tidak berhasil dengan kedua varian.')
