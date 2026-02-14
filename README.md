# [Dest0g3 520迎新赛] Mr.Doctor Writeup

## 题目信息

* **题目名称**：Mr.Doctor
* **来源**：Dest0g3 520迎新赛
* **分类**：Crypto
* **分值**：99

## 题目分析

题目给出了一个 Python 脚本 `task.py`，主要包含以下几个部分：

1. **SHA256 类**：将 Flag 分块（每4字节），计算每一块的 SHA256 哈希值，并将其转换为长整型存储在 `sha_flag` 列表中。

2. **RHODES_ELITE 类**：一个自定义的伪随机数生成器（PRNG）。
   
   * 状态转移公式：
   
   $s_{k+1} = (A \cdot s_k^2 + B \cdot s_k + C) \pmod N$
   
   * 输出：每次调用 `next()` 返回 $s_{k+1}$ 右移 12 位后的值。
   * 已知参数：$A, B, C, N$ (即 Amiya, Rosmontis, Blaze, Doctor)。

3. **加密逻辑**：
   
   * 生成一个 40 位的随机种子 `seed`。
   * 输出了 PRNG 的前两次迭代值 `Ash` 和 `SliverAsh`。
   * 最终的密文 $W$ 由 `sha_flag` 与 PRNG 输出异或生成：
   
   $W = \text{concat}(\text{long\_to\_bytes}(\text{sha\_flag}[i] \% \text{seed}^3 \oplus (\text{next\_out} \% 100)))$

我们的目标是恢复 `seed`，还原 PRNG 序列，进而反解出 Flag。

## 解题步骤

### 第一步：恢复 PRNG 中间状态

题目给出了 `Ash` 和 `SliverAsh`。根据代码逻辑，它们分别是状态 $s_1$ 和 $s_2$ 右移 12 位后的结果。

$Ash = s_1 \gg 12$

$SliverAsh = s_2 \gg 12$

虽然我们不知道 $s_1$ 的低 12 位，但由于只有 12 位未知（共 $2^{12}=4096$ 种可能），我们可以直接爆破。

对于每一个可能的 $s_1$，我们可以根据状态转移公式计算预测的 $s_2$：

$s_2 = (A \cdot s_1^2 + B \cdot s_1 + C) \pmod N$

如果预测的 $s_2$ 右移 12 位后等于 `SliverAsh`，则说明我们找到了正确的 $s_1$。

### 第二步：恢复初始种子 seed

已知中间状态 $s_1$，我们需要求解初始种子 $s_0$ (即 `seed`)。根据状态转移公式，有：

$A \cdot s_0^2 + B \cdot s_0 + C \equiv s_1 \pmod N$

这是一个模 $N$ 下的二次同余方程。整理后得到：

$A \cdot s_0^2 + B \cdot s_0 + (C - s_1) \equiv 0 \pmod N$

为了解这个方程，我们需要解模平方根。令 $\Delta = B^2 - 4A(C - s_1)$，我们需要找到 $\Delta$ 的平方根 $\sqrt{\Delta} \pmod N$。

由于 $N$ 是大素数，我们可以使用 **Cipolla 算法** 来求解模平方根。求出 $\sqrt{\Delta}$ 后，根据求根公式：

$s_0 = \frac{-B + \sqrt{\Delta}}{2A} \pmod N$

题目中提到 `seed` 是 `getRandomNBitInteger(40)` 生成的，这意味着正确的 $s_0$ 的比特长度应为 40。我们可以通过这个条件过滤出正确的种子。

### 第三步：解密 Flag

有了 `seed`，我们就可以初始化 PRNG 并重现加密时的随机数序列。

由于 Python 的 `long_to_bytes` 在转换整数时会自动去除前导零，导致我们无法确切知道 $W$ 中每一块的精确字节长度（通常在 14-16 字节波动）。我们需要在解密时尝试不同的块长度。

此外，已知 Flag 格式通常为 UUID 或类似格式，字符集有限（`0-9a-f-`），这大大缩小了爆破空间。

解密逻辑如下：

1. 计算当前的 PRNG 输出 `next_out`。
2. 尝试块长度 $L \in \{15, 14, 16, 13\}$。
3. 取 $W$ 的前 $L$ 个字节转为整数，与 `next_out % 100` 异或，得到 `target_val`。
4. 爆破 4 字节明文（字符集限制在 hex），计算其 SHA256 哈希值。
5. 检查 `bytes_to_long(sha256(plain).hexdigest()) % seed^3` 是否等于 `target_val`。
6. 匹配成功则记录明文，处理下一块。
- [ ] ```python
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
  ```
  
  ## 运行结果
  
  ```text
  [*] 正在恢复 s1...
  [+] 找到 s1: 4494800869822930172
  [*] 正在恢复 seed...
  [+] 找到 seed: 626844643882
  [*] 正在解密 Flag...
  [+] Block: d2a4
  [+] Block: d1af
  [+] Block: -8a8
  [+] Block: 0-87
  [+] Block: 94-9
  [+] Block: 9ac-
  [+] Block: 635f
  [+] Block: 8949
  [+] Block: 4cac
  [-] 解密中断。当前 Flag: d2a4d1af-8a80-8794-99ac-635f89494cac
  
  [+] Final Flag: Dest0g3{d2a4d1af-8a80-8794-99ac-635f89494cac}
  ```
  
  ## Flag
  
  ```text
  Dest0g3{d2a4d1af-8a80-8794-99ac-635f89494cac}
  ```
  
  ## 总结
  
  这道题是一道非常经典的 PRNG 状态恢复与密码学解密结合的题目。关键点在于：
  
  利用截断输出暴力破解低位信息。
  
  利用 Cipolla 算法求解二次同余方程以恢复种子。
  
  在解密阶段，利用已知字符集特性（UUID）优化爆破效率。
  希望这篇 Writeup 对你有所帮助！
