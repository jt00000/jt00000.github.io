---
layout: page
title: "KalmarCTF 2024 Symmetry 1, 2, 3"
date: 2024-03-22 00:00:00 -0000
---

同じバイナリを使って、3パートにわかれた問題です。

各パートのジャンルと、タグ、正答数は以下の通りです。
- Symmetry 1 (Rev, [Rev, Crypto], 42 solve)
- Symmetry 2 (Crypto, [Crypto, Rev, Pwn], 19 solve)
- Symmetry 3 (Pwn, [Crypto, Rev, Pwn], 13 solve)

このバイナリは簡易のAESのような暗号処理を実装していて、好きな回数暗号化処理をすることができます。

# 動作概要
## 入力部
まずブロック数を入力した後、鍵、シフト列、平文を入れていきます。ブロック長をnとしたとき、すべて8nバイトのサイズになります。

分かりにくいのですが、鍵と平文はバイト列をブロックごとに8バイト入力し、シフト列はnibble（4bit）の単位で16バイト入れるようになっています。

鍵と平文はあとでnibbleに分解されます。例えば0xbeefは`e, f, e, b`の順に分解されます。

```c
  do {
    while( true ) {
      printf("Number of blocks: ");
      __isoc99_scanf(&DAT_00102053,&local_4c);
      if (local_4c < 0x65) break;
      puts("That is a bit too much...");
    }
    key_array = calloc((ulong)local_4c,8);
    shift_array = calloc((ulong)local_4c,0x10);
    local_20 = calloc((ulong)local_4c,8);
    local_18 = calloc((ulong)local_4c,8);
    for (block = 0; block < local_4c; block = block + 1) {
      printf("Please provide a key for block %u: ",(ulong)block);
      for (i0 = 0; i0 < 8; i0 = i0 + 1) {
        __isoc99_scanf("%2hhx",(long)key_array + (ulong)(i0 + block * 8));
      }
      for (i1 = 0; i1 < 0x10; i1 = i1 + 1) {
        printf("Please provide shift %u for block %u: ",(ulong)i1,(ulong)block);
        __isoc99_scanf("%2hhx",(long)shift_array + (ulong)(i1 + block * 0x10));
      }
      printf("Please provide plaintext for block %u: ",(ulong)block);
      for (i2 = 0; i2 < 8; i2 = i2 + 1) {
        __isoc99_scanf("%2hhx",(long)plaintext_array + (ulong)(i2 + block * 8));
      }
    }
```

## 暗号化部
pythonコードのようなものに落とすと、以下のような実装です。
ブロックごとに切り出した平文に対して、ラウンドごとに遷移状態をシフト列と鍵を使って変化させ、それをもとにして平文を入れ替えていきます。

`shift`の関数は、何をやっているのか実はあまりよくわかっていません。いろいろ値を入れると、ある第一引数に対して、第二引数を0から15で振ってあげると、出力値は被らずに出てくるという特徴があります。

```python
def shift(val, idx):
    if val & 1 == 1:
        return ((((((val >> 1) - (idx >> 1)) * 2) & 0xe) - (idx & 1)) + 1) & 0xf
    else:
        return ((idx & 1) + ((idx >> 1) + (val >> 1)) * 2) & 0xf

randval = [9, 10, 8, 1, 14, 3, 7, 15, 11, 12, 2, 0, 4, 5, 6, 13];

for block in range(blocks):
    block_out = plain_text_array[block:block*8+8]
    for round in range(16):
        for i0 in range(16):
            sbox[randval[i0]] = shift(shift_array[i1], i0);
        for i1 in range(16):
            round_key[sbox[i1]] = block_out[i1];
        for i2 in range(16):
            round_key[i2] = shift(round_key[i2], key_array[i2]);
        for i3 in range(16):
            block_out = sbox[sbox[round_key[i3]]];
    ciphertext_array += block_out
```

# Symmetry 1
鍵と、シフトと、暗号文のペアが配布されています。

暗号処理のところを調べた結果、置き換えのところはsboxを復元できればよく、復元は`ciphertext`からできそうです。また`shift`は可逆の処理で、第二引数と、結果が分かっているので16パターン調べればよく、素直に逆の処理を実装して、回答を得ることができます。


```python
keys=[[2, 3, 3, 5, 3, 3, 1, 4, 1, 1, 3, 3, 1, 2, 2, 0], [5, 1, 5, 4, 7, 3, 2, 0, 0, 1, 7, 1, 0, 6, 2, 7], [2, 6, 6, 0, 5, 6, 5, 1, 6, 4, 7, 1, 1, 7, 3, 1], [4, 3, 0, 5, 2, 0, 4, 2, 7, 7, 7, 1, 1, 1, 7, 5], [1, 0, 0, 0, 4, 5, 3, 6, 3, 4, 7, 6, 4, 0, 1, 2], [5, 5, 7, 1, 3, 1, 7, 6, 6, 3, 1, 1, 2, 4, 6, 7], [2, 6, 2, 4, 1, 6, 0, 3, 7, 0, 6, 3, 0, 6, 7, 3]]
shifts=[[0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0], [0, 1, 3, 5, 0, 1, 1, 0, 0, 1, 3, 5, 0, 1, 1, 0]]
ciphertexts=[[8, 12, 10, 7, 2, 6, 3, 2, 14, 1, 8, 4, 2, 12, 9, 15], [10, 13, 5, 2, 13, 12, 11, 5, 14, 5, 3, 12, 4, 11, 0, 9], [10, 4, 0, 3, 9, 13, 13, 2, 2, 1, 0, 4, 3, 15, 11, 12], [7, 13, 1, 13, 9, 9, 9, 10, 9, 12, 3, 0, 1, 10, 7, 12], [13, 3, 10, 6, 9, 9, 2, 13, 1, 10, 13, 0, 4, 2, 1, 0], [6, 2, 2, 2, 15, 9, 12, 4, 7, 6, 2, 15, 1, 10, 14, 7], [10, 12, 6, 14, 14, 2, 14, 12, 15, 0, 15, 0, 8, 9, 4, 2]]
randarr = [9, 10, 8, 1, 14, 3, 7, 15, 11, 12, 2, 0, 4, 5, 6, 13]

def n2b(nibble):
    out =''
    for i in range(0, len(nibble), 2):
        out += chr(nibble[i]*0x10+nibble[i+1])
    return out

def b2n(by):
    blocks = (len(by) // 8) + 1
    out = []
    tmp = []
    for b in by:
        tmp.append(b >> 4)
        tmp.append(b & 0xf)
        if len(tmp) == 0x10:
            out.append(tmp)
            tmp = []
    if tmp != []:
        while(len(tmp) < 0x10):
            tmp.append(0)
        out.append(tmp)
    return out

def shift(val, idx):
    if val & 1 == 1:
        return ((((((val >> 1) - (idx >> 1)) * 2) & 0xe) - (idx & 1)) + 1) & 0xf
    else:
        return ((idx & 1) + ((idx >> 1) + (val >> 1)) * 2) & 0xf

def invshift(shifted, idx):
    for i in range(0x10):
        ret = shift(i, idx)
        if ret & 0xf == shifted:
            return i
    assert False, "something wrong"

def get_nibble(buf, idx):
    return buf[idx]

def set_nibble(buf, idx, val):
    buf[idx] = val

def reverse(ct, karr= keys, sarr=shifts, nb=0):
    block_out = ct
    round_key = [0] * 0x10

    sboxes = []
    for i in range(0x10):
        sbox = [0] * 0x10 
        for j in range(0x10):
            sel = randarr[j] 
            val = shift(sarr[nb][i], j)
            sbox[sel] = val
        sboxes.append(sbox)

    for rnd in range(0x10):
        sbox = sboxes[0xf-rnd]
        round_key = [0] * 0x10

        for i3 in range(0x10):
            val1 = get_nibble(block_out, i3)
            val2 = sbox.index(sbox.index(val1))
            set_nibble(round_key, i3, val2)
 
        for i2 in range(0x10):
            val1 = get_nibble(karr[nb], i2)
            val2 = get_nibble(round_key, i2)
            val3 = invshift(val2, val1)
            set_nibble(round_key, i2, val3)
 
        for i1 in range(0x10):
            val1 = get_nibble(round_key, sbox[i1]) 
            set_nibble(block_out, i1, val1)

    return block_out

flag = ''
for i, c in enumerate(ciphertexts):
    flag += n2b(reverse(c, nb=i))
print(flag)
```

`kalmar{nice!_now_please_try_the_other_two_parts}`

# Symmetry 2
この問題はメインのジャンルがCryptoになります。（結論、個人的にはあまりCrypto要素はなかったですが。）

暗号化処理の開始時に、スタックにフラグをコピーしてそうなところがあることが分かります。これを出力することが目的と思われます。

```
        0010160b 48 89 45 f8     MOV        qword ptr [RBP + local_10],RAX
        0010160f 31 c0           XOR        EAX,EAX
        00101611 48 b8 6b        MOV        RAX,0x667b72616d6c616b
                 61 6c 6d 
                 61 72 7b 66
        0010161b 48 ba 61        MOV        RDX,0x67616c665f656b61
                 6b 65 5f 
                 66 6c 61 67
        00101625 48 89 45 90     MOV        qword ptr [RBP + local_78],RAX
        00101629 48 89 55 98     MOV        qword ptr [RBP + local_70],RDX
        0010162d 48 b8 5f        MOV        RAX,0x7365745f726f665f
                 66 6f 72 
                 5f 74 65 73
        00101637 48 ba 74        MOV        RDX,0x7d293a5f676e6974
                 69 6e 67 
                 5f 3a 29 7d
```

スタックのレイアウトは以下の通りです。`sbox[0x80]`に位置するところに、フラグが格納されます。

```
0x7ffe448519f0: 0x9999999999999999      0x9999999999999999 --- round_key[8], block_out[8]
0x7ffe44851a00: 0x060e0d0c050a030b      0x07040f0908010002 --- sbox[16]
0x7ffe44851a10: 0x00007ffe44851b50      0x00007b4248e62142
0x7ffe44851a20: 0x0000003000000008      0xc49e839dffa49b00
0x7ffe44851a30: 0x00007ffe44851a40      0x0000000000000000
0x7ffe44851a40: 0x00007ffe44851af0      0x0000563edee216af
0x7ffe44851a50: 0x0000000000000007      0x0000563edef6d300
0x7ffe44851a60: 0x0000563edef6d2e0      0x0000563edef6d2c0
0x7ffe44851a70: 0x0000563edef6d2a0      0x0000000100000008
0x7ffe44851a80: 0x667b72616d6c616b      0x67616c665f656b61 --- flag = sbox[0x80]
0x7ffe44851a90: 0x7365745f726f665f      0x7d293a5f676e6974
```

暗号化部の実際の実装は以下の通りです。set/getの関数に引数のチェックがなく、範囲外を読むことができます。

```c
void do_encrypt(uint blocks,long key_array,long shift_array,long plaintext_array,long ciphertext_array)

/*...*/

  for (block = 0; block < blocks; block = block + 1) {
    block_out = *(undefined8 *)(plaintext_array + (ulong)(block << 3));
    for (round = 0; round < 0x10; round = round + 1) {
      for (i0 = 0; i0 < 0x10; i0 = i0 + 1) {
        x = (&randval)[(int)(uint)i0];
        y = shift(*(undefined *)(shift_array + (ulong)(round + block * 0x10)),i0);
        sbox[(int)(uint)x] = y;
      }
      for (i1 = 0; i1 < 0x10; i1 = i1 + 1) {
        val = get_nibble(&block_out,i1);
        set_nibble(round_key,sbox[(int)(uint)i1],val); // oob write
      }
      for (i2 = 0; i2 < 0x10; i2 = i2 + 1) {
        val = get_nibble(key_array + (ulong)(block << 3),i2);
        uVar1 = get_nibble(round_key,i2);
        x = shift(uVar1,val);
        set_nibble(round_key,i2,x & 0xf);
      }
      for (i3 = 0; i3 < 0x10; i3 = i3 + 1) {
        x = get_nibble(round_key,i3);
        set_nibble(&block_out,i3,sbox[(int)(uint)sbox[(int)(uint)x]]); // oob read
      }
    }
    *(undefined8 *)((ulong)(block << 3) + ciphertext_array) = block_out;
  }

/*...*/
```

以下のようにゴールから考えました。
- flagのうちどこか1バイトを暗号文にして出力させる
- `sbox[sbox[x]]`が0x8Xを指すようにする
- `sbox[0:16]=0x8X`となるようにする（sboxの先頭16バイトのどこかに0x8Xが入ればよい）

sboxへの代入は上記の`i0`のループで、`shift(shift_array[round], i0)`の値が入ります。事前の調査で、`shift`の第一引数は`0x80`を選ぶと、第二引数の値にかかわらず`0x8X`が出てくることが分かっているので、`shift_array`に `0x80`を入れることで、`sbox[0:16]`を`0x8X`で埋めることができます。

これで上手くいくと思いきや、まだ少し問題があります。`block_out`への出力は次のラウンド以降も使われてしまうため、`round_key`が変化し、結果次の`block_out`への出力に余計なものが混ざってフラグを取り出せなくなります。

簡単にはすべての`shift_arary`を`0x80`にしてしまえば良さそうと思いますが、これは別の問題があります。`round_key`は未初期化変数になっていて、ここにはポインタが配置されています。これを掃除しない限り、暗号文の出力結果がASLRにも依存してしまい、毎回出力が変わります。

そこで、1ラウンド目で`round_key`にちゃんと書き込みをして、以降は`sbox`に`0x80`が入り続けるように、`shift_array`を`[0, 0x80, 0x80, 0x80, ...]`という構成にしたところ、鍵が固定され、うまくフラグだけが並べ替えられて出てきます。

`round_key`に入れるバイト列は`plaintext_array`から調整できますが、8バイト全てを同じにしておくことで特定の1文字が出てくるようになります。並び替えの順番は`randval`に依存しているだけなので、何文字目を取り出したいかを指定することができます。

あとは`set_nibble`の仕様上、ニブルの計算はマスクなしの加算になってしまっているので、上手く出力結果を戻してあげて、フラグを復元します。

例えば `}`の出力は`Block 0: 4d4d4d4d4d4d4d4d`となります。これは`set_nibble`で`(0x7d*0x10+0x7d) & 0xff`という計算が行われるためであるので、これも逆の処理を書いてあげることで解決します。

スクリプトは[ここ](https://github.com/jt00000/ctf.writeup/blob/master/kalmar2024/symmetry/sym2.py)。

`kalmar{u_c4n_r34d!n0w_d0_wR1t1n}`

# Symmetry 3
今度は書き込みが必要です。oob writeはスタック変数なので、ROPが組めそうです。リークは2番と同等の方法でスタックから取得しておきます。

書き込みは先ほどの実装のうち、
```
        val = get_nibble(&block_out,i1);
        set_nibble(round_key,sbox[(int)(uint)i1],val);
```

というところを使って書き込みをします。`set_nibble`の第二引数は割って使われる点に注意する必要があります。

2番で使ったoob readは`sbox[x]`を1バイト読んだとき、同時に`round_key[x//2]`には4ビット書いています。`x`が偶数の時はnibbleの上側（ & 0x0f0相当 ）、奇数の時は下位側（ & 0x0f相当 ）を書きます。

スタックのレイアウトは以下の通りです（再掲）。今回はリターンアドレスを狙いたいので、`round_key`から+0x58に位置するところを狙って書き換えます。

```
0x7ffe448519f0: 0x9999999999999999      0x9999999999999999 --- round_key[8], block_out[8]
0x7ffe44851a00: 0x060e0d0c050a030b      0x07040f0908010002 --- sbox[16]
0x7ffe44851a10: 0x00007ffe44851b50      0x00007b4248e62142
0x7ffe44851a20: 0x0000003000000008      0xc49e839dffa49b00
0x7ffe44851a30: 0x00007ffe44851a40      0x0000000000000000
0x7ffe44851a40: 0x00007ffe44851af0      0x0000563edee216af --- return address
0x7ffe44851a50: 0x0000000000000007      0x0000563edef6d300
0x7ffe44851a60: 0x0000563edef6d2e0      0x0000563edef6d2c0
0x7ffe44851a70: 0x0000563edef6d2a0      0x0000000100000008
0x7ffe44851a80: 0x667b72616d6c616b      0x67616c665f656b61
0x7ffe44851a90: 0x7365745f726f665f      0x7d293a5f676e6974
```

`shift_array`を`0xb0`にすれば、リターンアドレスに書き込むことができます。書き込みは1ラウンドだけ書き込んで、あとは影響のないところに捨てればよいのでさっきとは逆で `shift_array`は`[[0xb0]+[0]*0xf]`と指定します。あとは鍵に応じて置換場所が変わるので、平文として`0123456789abcdef`など事前に入力して、置き換え位置を見て調整します。

8バイトしか書き込めていないので、one_gadgetか、copでコード実行につなぐ必要があります。（複数のROPを書くこともできると思いますが今回不要でした。）

リターンしたときの状況は以下の通りです。そのままコントロールできそうなヒープアドレスがいい位置にありますが、今回はone_gadgetにいいものが見つかりました。

```
───────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x0               
$rcx   : 0x00007ffce787ce38  →  0xcccccccccccccccc
$rdx   : 0x00006353c4dcd3e0  →  0xcccccccccccccccc
$rsp   : 0x00007ffce787ce88  →  0xdfaddaeeeebeedfb
$rbp   : 0x00007ffce787cf30  →  0x00007ffce787cf90  →  0x0000000000000001
$rsi   : 0xf               
$rdi   : 0x00007ffce787ce38  →  0xcccccccccccccccc
$rip   : 0x00006353c41325d6  →   ret 
$r8    : 0x00006353c4dcd3e0  →  0xcccccccccccccccc
$r9    : 0x0               
$r10   : 0x0               
$r11   : 0x00007cc03a3bf3c0  →  0x0002000200020002
$r12   : 0x00007ffce787d0a8  →  0x00007ffce787f2d8  →  "./challenge"
$r13   : 0x00006353c41326c6  →   endbr64 
$r14   : 0x00006353c4134d88  →  0x00006353c41321e0  →   endbr64 
$r15   : 0x00007cc03a577040  →  0x00007cc03a5782e0  →  0x00006353c4131000  →   jg 0x6353c4131047
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────── stack ────
0x00007ffce787ce88│+0x0000: 0xdfaddaeeeebeedfb   ← $rsp
0x00007ffce787ce90│+0x0008: 0x0000000000000007
0x00007ffce787ce98│+0x0010: 0x00006353c4dcd3e0  →  0xcccccccccccccccc
0x00007ffce787cea0│+0x0018: 0x00006353c4dcd3c0  →  0xbeefbeefdeaddead
0x00007ffce787cea8│+0x0020: 0x00006353c4dcd3a0  →  0x00000000000000b0
0x00007ffce787ceb0│+0x0028: 0x00006353c4dcd380  →  0x0000000000000000
0x00007ffce787ceb8│+0x0030: 0x00000001c4135020
0x00007ffce787cec0│+0x0038: "kalmar{fake_flag_for_testing_:)}"
─────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x6353c41325cc                  call   0x6353c41320f0 <__stack_chk_fail@plt>
   0x6353c41325d1                  mov    rbx, QWORD PTR [rbp-0x8]
   0x6353c41325d5                  leave  
●→ 0x6353c41325d6                  ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "challenge", stopped 0x6353c41325d6 in ?? (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x6353c41325d6 → ret 
────────────────────────────────────────────────────────────────────────────────────────────
gef➤  
```

対応するone_gadgetはこちらです。rdxは出力される暗号文なので、鍵で調整できます。

```
0xebc85 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
```

ここまでを全てつないで完成です。

スクリプトは[ここ](https://github.com/jt00000/ctf.writeup/blob/master/kalmar2024/symmetry/sym3.py)。


```
[+] Opening connection to chal-kalmarc.tf on port 8: Done
    -> stack_leak: 0x7ffd4c419490
    -> base: 0x7f078d22c000
    -> one: 0x7f078d317c85
0x3d705078080071fc
[*] Switching to interactive mode
$ ls
challenge
$ cd /
$ ls
app   etc                     lib32     mnt   run   tmp
bin   flag-8c55b233b9cc00a04d500f327064c975.txt  lib64     opt   sbin  usr
boot  home                     libx32  proc  srv   var
dev   lib                     media     root  sys
$ cat flag-8c55b233b9cc00a04d500f327064c975.txt
kalmar{1n_th3_3nd_it_15_jus1_4_s1mp13_r0p_Ch41n}
```

最後の問題は1時間しかなかったのですが、並び替えを急いで調べる、one_gadgetの制約を満たすために鍵を差し替える、鍵を変えたせいで並び替え順が変わったことに気づく、となったところで調べなおしていたら15分タイムオーバーで完成しました。悔しい。

前半は暗号ロジックを普通に解析するが、後半はバグを含めて考える必要があるという構成で、pwnの立場としては面白かったです。