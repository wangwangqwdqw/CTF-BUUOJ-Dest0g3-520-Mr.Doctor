import string
from hashlib import sha256
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse

# ----------------------------
# 题目给出的参数
# ----------------------------
Amiya = 956366446278
Rosmontis = 1061992537343
Blaze = 636205571590
Doctor = 18068433704538283397
Ash = 1097363493609113
SliverAsh = 2051431344160327
W_int = 1920358673646340365826516899186299898354902389402251443712585240681673718967552394250439615271108958695077816395789102908554482423707690040360881719002797624203057223577713119411615697309430781610828105111854807558984242631896605944487456402584672441464316236703857236007195673926937583757881853655505218912262929700452404084

# ----------------------------
# 1. 恢复 PRNG 状态 s1
# ----------------------------
print("[*] 正在恢复 s1...")
s1 = -1
for low_bits in range(4096):
    # Ash 是 s1 的高位，补上猜测的低位
    candidate_s1 = (Ash << 12) | low_bits
    # 验证 s2 是否匹配
    val = (Amiya * candidate_s1 * candidate_s1 + Rosmontis * candidate_s1 + Blaze) % Doctor
    if (val >> 12) == SliverAsh:
        s1 = candidate_s1
        print(f"[+] 找到 s1: {s1}")
        break

if s1 == -1:
    print("[-] 未能恢复 s1")
    exit()

# ----------------------------
# 2. 恢复 seed (s0)
# ----------------------------
# 需要解方程: A*s0^2 + B*s0 + C - s1 = 0 (mod Doctor)
print("[*] 正在恢复 seed...")

def mod_sqrt(n, p):
    """使用 Cipolla 算法求解模平方根"""
    n %= p
    if n == 0: return 0
    if p == 2: return n
    # 勒让德符号判断是否存在解
    if pow(n, (p - 1) // 2, p) != 1:
        return None

    # 寻找 a 使得 a^2 - n 是非二次剩余
    a = 0
    while True:
        a += 1
        w = (a * a - n) % p
        if pow(w, (p - 1) // 2, p) == p - 1:
            break
    
    # 定义复数域乘法 (x + y*sqrt(w))
    def mul(point1, point2, w_val):
        x1, y1 = point1
        x2, y2 = point2
        return (x1 * x2 + y1 * y2 * w_val) % p, (x1 * y2 + x2 * y1) % p

    # 快速幂计算 (a + sqrt(w))^((p+1)/2)
    res = (1, 0)
    base = (a, 1)
    exponent = (p + 1) // 2
    
    while exponent > 0:
        if exponent & 1:
            res = mul(res, base, w)
        base = mul(base, base, w)
        exponent >>= 1
        
    return res[0]

# 计算判别式 Delta
c_term = (Blaze - s1) % Doctor
delta = (Rosmontis * Rosmontis - 4 * Amiya * c_term) % Doctor

sqrt_delta = mod_sqrt(delta, Doctor)
if sqrt_delta is None:
    print("[-] 无法解出平方根")
    exit()

inv_2A = inverse(2 * Amiya, Doctor)
seed = -1

# 尝试两个根
roots = [sqrt_delta, (Doctor - sqrt_delta) % Doctor]
for root in roots:
    s0 = ((-Rosmontis + root) * inv_2A) % Doctor
    # getRandomNBitInteger(40) 生成的数 bit_length 应为 40
    if s0.bit_length() == 40:
        seed = s0
        print(f"[+] 找到 seed: {seed}")
        break

if seed == -1:
    print("[-] 未找到合适的 seed")
    exit()

# ----------------------------
# 3. 生成后续的 PRNG 输出
# ----------------------------
class RHODES_ELITE:
    def __init__(self, seed):
        self.Doctor = Doctor
        self.Amiya = Amiya
        self.Rosmontis = Rosmontis
        self.Blaze = Blaze
        self.seed = seed

    def next(self):
        self.seed = (self.Amiya * self.seed * self.seed + self.Rosmontis * self.seed + self.Blaze) % self.Doctor
        return self.seed >> 12

elite = RHODES_ELITE(seed)
elite.next() # 对应 Ash
elite.next() # 对应 SliverAsh

# ----------------------------
# 4. 解密 Flag
# ----------------------------
W_bytes = long_to_bytes(W_int)
mod_val = seed ** 3

# 优化：假定 Flag 为 UUID 格式，字符集为 0-9, a-f, -
charset = string.digits + "abcdef" + "-"
print("[*] 正在解密 Flag...")

flag = b""

def solve_block(w_part, next_val):
    target_x = next_val % 100
    # 尝试不同的块长度 (long_to_bytes 可能导致长度变化)
    for length in [15, 14, 16, 13]:
        if length > len(w_part): continue
        current_w_int = bytes_to_long(w_part[:length])
        sha_val_mod = current_w_int ^ target_x
        
        # 爆破 4 字节明文
        for c1 in charset:
            for c2 in charset:
                for c3 in charset:
                    for c4 in charset:
                        block = c1.encode() + c2.encode() + c3.encode() + c4.encode()
                        h = sha256(block).hexdigest().encode()
                        h_int = bytes_to_long(h)
                        if h_int % mod_val == sha_val_mod:
                            return block, length
    return None, 0

while True:
    next_out = elite.next()
    decoded_block, length = solve_block(W_bytes, next_out)
    
    if decoded_block:
        flag += decoded_block
        W_bytes = W_bytes[length:]
        # 打印进度
        print(f"[+] Block: {decoded_block.decode()}")
        if flag.endswith(b'}'):
            break
    else:
        print(f"[-] 解密中断。当前 Flag: {flag.decode(errors='ignore')}")
        break

print("\n[+] Final Flag: Dest0g3{" + flag.decode(errors='ignore')+"}")
