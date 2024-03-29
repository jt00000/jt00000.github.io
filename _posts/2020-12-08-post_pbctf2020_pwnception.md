---
layout: page
title: "pbctf2020 pwnception"
date: 2020-12-08 00:00:00 -0000
---

unicornで書かれたバイナリを攻略する問題です。時間切れでしたが楽しく解けましたので書き残します。

## tl dr
- userlandはbfを書いてropを作ります。ガジェットを上手く使うことで、rdi,rsi,rdx,raxの値をコントロールすることができます。
- kernelはraxに大きな値を入れることで、共有メモリを指せるようになります。またアドレス制限なしの書き込みガジェットがあるので、これを利用してropを作りmmapを動作させることを目指します。raxの値を`mov rax, r11; ret;`を使って調整すること、`r11`は１番のシステムコールの文字数で指定することの２つがポイントです。さらにmmapを使ってスタックをrwxになったところにシェルコードを書き込みます。
- malloc, freeはスレッドで行われるため、main_arenaの値を出力しないです。が、代わりにunicornの関数のアドレスがリークできるので、そこからgotをたぐってlibcをリークし、free_hookを編集します。
- exploitは[こちら](https://github.com/jt00000/ctf.writeup/blob/master/pbctf2020/pwnception/dist/challenge/solve.py)

## ファイルの構成と概要
問題は３つのファイルで構成されています。
- main: unicornの上でuserlandとkernelのバイナリを動作させます。各ゲスト内での特定のコードや割り込みに反応して処理する機能があります。
- userland: ゲスト１。普通に単体で起動しても動作するelfです。staticコンパイルされています。
- kernel: ゲスト２。こちらは単体では起動できなくなっています。mainを経由した接続によって、userlandにおけるシステムコールに反応して処理する機能があります。

これらの他にライブラリとして、`libc.so.6`と、`libunicorn.so.1`が付属しています。libcはdouble freeが塞がれたglibc2.27です。  
起動は `LD_PRELOAD=./libunicorn.so.1 ./main ./kernel ./userland`で行います。

## mainの解析
mainはまず２つのスレッドを立ち上げます。
![](/assets/pwnception/2020-12-08-22-25-01.png)

### kernel側のスレッド
kernel_taskから見ていきます。
まずkernelは固定のアドレスでマップされます。

| addr | size | rwx |
| --- | --- | --- | 
| 0x7fffffeff000 | 0x100000 | rw |
| 0xffff8801ffeff000 | 0x100000 | rw |
| 0xffffffff81000000 | 0x100000 | rx |

この内ファイル`kernel`の内部はそのまま0xffffffff81000000に格納されます。  
その後、いくつかの割り込みハンドラを登録し、rsp、ripをセットして起動します。  
0x7fffffeff000はuserlandの解析で判明しますが、共有メモリのようです。

![](/assets/pwnception/2020-12-08-22-30-47.png)

uc_〜の命令は調べても情報が少ないこともあり、過去にやった問題やメモなどから引数の意味をなんとなく推測したりします。特にuc_reg_write、uc_reg_readの２つ目の引数で利用される以下の定数とレジスタの組み合わせは、この問題ではかなり重要です。  

| 定数 | レジスタ | 
| --- | --- |
| UC_X86_REG_RAX | 0x23 |
| UC_X86_REG_RDI | 0x27 |
| UC_X86_REG_RSI | 0x2b |
| UC_X86_REG_RSP | 0x2c |
| UC_X86_REG_RIP | 0x29 |

kernel側の割り込みハンドラで重要なのは２つです。  

#### kernel_code_handler
１コード実行するたびに呼ばれていて、特定のバイト列だった場合に処理に移ります。
- f4 (hlt): 動作を停止します。避けたい処理。
- cf (iret): raxをuserlandに返してます。その後sem_postして待機します。
- f3 90 (pause): sem_postして待機します。

![](/assets/pwnception/2020-12-08-22-46-21.png)

#### kernel_intr_handler
こちらはkernel内で`int`命令が走ったときに反応します。２つ目の引数に割り込み番号が入ります。0x70と0x71に反応します。  
- int 0x70: raxの値に応じてkernel内で処理が進みます。
    - rax = 0xf: segvのフラグを立てます。
    - rax = 0xa: 仮想kernelのmprotect
    - rax = 0x9: 仮想kernelのmmap

- int 0x71: こちらもraxの値に応じて、今度はホストで処理が進みます。チャンクのmalloc、free、仮想kernelメモリへの書き込み読み込みを行います。チャンクサイズ制限無く読み書きができます。

![](/assets/pwnception/2020-12-08-23-36-18.png)

### userland側のスレッド
コード省略します。0x600000000000と0x7fffffeff000をrwでマップします。  
こちらは割り込みハンドラは１つだけで、システムコールをkernelにつなぎます。

## userlandの解析
x86_64のバイナリです。これ単独で普通に動作させることができます。

![](/assets/pwnception/2020-12-09-19-26-40.png)

bfで入力を受け付け、!で入力終了を通知します。バッファサイズは0x1000ほどです。入力を受けた後は、普通のbf処理が実装されています。

![](/assets/pwnception/2020-12-09-19-33-35.png)

`[.,`などが使えますので入出力は簡単です。またカーソル移動を示す`>`(0x3e)や`<`(0x3c)に範囲チェックがないので、スタックアドレスのリークやリターンアドレスの書き換えが可能であることが分かります。何でもできそうですが、楽なのはropでしょう。使いたいレジスタに関してガジェットを探してみると、syscallとraxは簡単なものが見つかりますが、rdi,rsi,rdxは見つからないことが分かります。あまり役に立た無さそうなr12, r13, rbxも簡単なガジェットが見つかります。

rdi, rsi, rdxの３つに関しては以下のガジェットを組み合わせることで上手く行きます。  
まず、rdiですが、rsiをコントロールできれば良いことが分かります。このとき、システムコールで落ちないように、またkernelでトラップされないようなraxを適当な値にしておきます。今回は9（mmap）で作ってみました。適当な引数ではまず通らないので、エラーが返って処理が続くと思います。書きながら思いましたが、1や2も良いかも知れません。

```
807   400d11:   48 89 f7                mov    rdi,rsi
808   400d14:   48 89 d6                mov    rsi,rdx
809   400d17:   48 89 ca                mov    rdx,rcx
810   400d1a:   4d 89 c2                mov    r10,r8
811   400d1d:   4d 89 c8                mov    r8,r9
812   400d20:   4c 8b 4c 24 08          mov    r9,QWORD PTR [rsp+0x8]
813   400d25:   0f 05                   syscall
814   400d27:   c3                      ret
```

残りのrdxとrsiですが、以下のガジェットを使います。先の調査でr12, rbx, r13は簡単に設定できるので、r13を`ret`を指すようにすれば、無事rdxとrsiの値をコントロールすることができます。

```
0x004008bd: mov rdx, r12 ; mov rsi, rbx ; call r13 ;
```

さて、userlandの解析の結果、これでほとんど自由にシステムコールが呼べるようになりました。mainに戻ることも、rbpを復帰させることも可能です。（結局使いませんでしたが）

## kernelの解析

カーネルはmainで、ripを`0xFFFFFFFF81000000`として起動されていました。  
このアドレスではjmp命令が置いてあって、テーブルの値に応じて飛び先が変わっています。このケースでは赤丸で囲ったところ、まずは`0xFFFFFFFF8100002d`に飛ぶようです。アドレスが命令のすぐ隣に来ているため、見にくくなっていることに、やりながら気づけました。ghidraでは`c`で選択範囲をdisassembleを解除して、`d`で選択範囲をdisassembleできるので、これを上手く利用しながら、命令列として見るべきところ、アドレスや文字列として見るべきところを整理していきます。

![](/assets/pwnception/2020-12-09-19-56-23.png)

次に`0xFFFFFFFF8100002d`ですが、rsiに文字列`Kernel has booted`の先頭のアドレスを入力し、文字数（0x12）をecxにつめて、`rep outsb`で出力した後、`pause`に落ちるようです。  

![](/assets/pwnception/2020-12-09-19-58-51.png)

確かに`LD_PRELOAD=./libunicorn.so.1 ./main ./kernel ./userland`で起動したときには文字列が出ていることが確認できます。

![](/assets/pwnception/2020-12-09-20-02-16.png)

pauseから先はmainで解析したとおり、sem_postしてuserlandに処理を任せ、userlandではsyscallを起点にsem_postが行われ、kernelが再開します。

userlandで発されたシステムコールは、mainで以下のように処理されています。
- segvフラグが０：userlandの引数になってるレジスタの値をセットして`0xFFFFFFFF81000007`へ
- segvフラグが１：`0xFFFFFFFF8100000E`へ

このアドレスは先ほどと同じ手順で見ていけば良さそうです。segvのパスは省略します。  
`0xFFFFFFFF81000007`は、すぐにシステムコールのテーブルにアクセスします。raxの値をチェックしていません。  

![](/assets/pwnception/2020-12-09-20-17-23.png)

したがって、以下の数式でraxの値でを設定することでほぼ任意の場所に飛ぶことができます。
```
rax = 0x10000000000000000 + target_addr - (0xffffffff81000000 + 0x900)) / 8
```

またシステムコールのテーブルそのものはかなりシンプルで、raxが0, 1, 3のときの他、0xf、0x9eでint 0x70が発されるほか、hltにつながる番号があります。しかし、ほとんどは下記のようにunimplementedと表示されるだけの関数に飛びます。（赤丸がint 0x70に飛ぶ貴重なアドレス）

![](/assets/pwnception/2020-12-09-20-19-53.png)

システムコールの実装を1つずつ見ていきます。

まずはrax=0で、readっぽい実装になっています。注目はアドレスを限定している点で、高位のアドレスへの書き込みはできないようになっています。

![](/assets/pwnception/2020-12-09-20-28-48.png)

rax=1も似たような形で、今度は書き込みをやります。

![](/assets/pwnception/2020-12-09-20-30-57.png)

少し難しいのがrax=2です。`open?`と名付けたままほったらかしにしていますが、openではありません。この関数はrdiで指定されたアドレスをスタックに格納し、rdiをインクリメントして格納してを繰り返し、`[rdi]=0`になるまで同じ処理を続けます。この処理が終わると、繰り返した回数分（つまり文字数）をrsiにつめて、出力する関数を呼びます。`printf("%s", buf)`のような出力ですね。この処理が終わると、今度は`cannot be opened`を出力します。この文字列は意味がよくわかりません。

![](/assets/pwnception/2020-12-09-20-32-16.png)

１つのポイントは、rdiの範囲がチェックされていないことですが、kernelはランダムになっているアドレスは無いため、特に読みたい値はありません。

## exploit方針検討
これで解析パートは終わりです。難しい脆弱性は無いですが、パーツが足りなそうな気もしますし、実際競技時間中はここで手詰まりになりました。  
結局、方針は以下のように整理検討すればよいです。  

1. 最終目的はmainを見ても明らかな通り、malloc、freeを利用してheapを攻めることでしょう。
2. malloc, freeはkernelからint 0x71を撃たないといけません。しかしkernelにそのようなコードはありません。したがって、kernelでシェルコードを書く必要があるでしょう。
3. シェルコードを書くためには、kernelのいずれかの領域をmmapする必要があります。
4. mmapはkernel からint 0x70割り込みが上がったときに、raxが0x9だと使えます。つまり,kernelでint 0x70を撃ったときに、raxに0x9がセットされ、かつrdi, rsi, rdxがmmapに成功するような値になっている必要があります。

この問題の最大の課題がここになります。仮に共有メモリに`int 0x70; ret;`ガジェットを指すアドレスを向けて、raxを共有メモリを指すようにセットしてuserlandからシステムコールを撃ったとしても、raxはでたらめな値になっていて、mmapを呼ぶことができません。まずはなんとかしてkernelでraxの値を調整しないといけません。  
結論を書くと、raxはr11がコントロールできれば以下の`mov rax, r11; ret`が利用できます。またr11は以下の関数においてrdxから引き継ぎますが、これはwriteで出力する文字数を示す数です。したがってuserlandから`write(1, addr, 0x9)`のシステムコールを事前に撃っておけば、ropでこのガジェットを通ることでraxを任意の値にセットできることが分かります。

![](/assets/pwnception/2020-12-09-20-47-50.png)

ropが必要なことが分かったため、今度は任意書き込みしてくれそうなガジェットを探します。探す場所も少ないので、すぐに都合の良い関数が見つかります。

![](/assets/pwnception/2020-12-09-20-53-08.png)

誰からも呼ばれていなかったので無視していましたが、かなり乱暴なガジェットです。実質制限なしreadです。rdi、rsiをそのまま入れています。任意アドレス任意長で入力できます。更にポイントなのが、r11を触っていないことです。r11の値をコントロールした後にこの制限なしreadを読んでも、その後でraxの値を安全にコントロールすることができます。

あとはkernelのリターンアドレスを考えますが、これはrspとして最初に指定された`0xffff8801ffeff000`から8引いたものと考えればよいです。理由は、システムコールのテーブルはcallで呼ばれているためです。  
ここまでを一旦まとめます。

手順１ userlandのropを作成
1. システムコール0番を利用して、共有メモリにkernelの制限なしreadの関数アドレスを入力
2. システムコール1番を利用して、kernelのレジスタr11を0x9にセット
3. 1で用意した制限なしread関数を利用して、kernelのスタックへropを書き込む
    - このとき、最終的にkernelのmmapが成功するようにアラインメントに気をつける必要があります
    - このwriteupではrdi: kernel_rsp-0x1000, rdx: 0x2000として説明します
    - mmapのアラインメントの関係で大きなペイロードを書くことになりますが、狙いはkernel_rsp-8以降です

手順２ kernelのropを作成
1. `mov rax, r11; ret`を使ってraxを0x9にセット
2. `int 0x70; ret`で割り込みを上げる。これによってmmapが呼ばれ、kernel_rsp+0x1000以降がrwxになる
    - これ、理由としては、手順１の３でrsp-0x1000から+0x2000を書き込んだので、rdiがrsp+0x1000を指すためです。
3. 再び制限なしread関数を利用して、今度はkernel_rsp+0x1000以降にシェルコードを書き込む
    - 手順１の時点で全部書けるのでは？と一瞬思いますが、書けません。理由２は上で書いたとおり、手順１の３で書き終えたポインタを先頭にしてmmapが動作するためです。
4. kernel_rsp+0x1000へリターンしてシェルコードを実行する

手順２を作る際のポイントですが、ガジェット１つ１つでiretを使って、userlandに戻るようにすることで、そこまでのropが成功していることを確認すると良いです。特にunicorn内部のバイナリのレジスタ状態が掴みにくいので、mainの随所にbreakを置いて観察することが重要です。  

---

最後に残ったのはmalloc freeです。典型的なノート問のような面構えです。明らかにuafですし、mallocのサイズチェック、read, writeの範囲チェックもありません。

![](/assets/pwnception/2020-12-09-21-35-08.png)

少し考えなければいけないのは、これらの関数を利用したとしても、外から入力する手段は無いということです。つまり`uc_mem_write/read`は、ホストのバイナリのメモリをゲストのバイナリのメモリに書いたり、その逆をやったりしますが、例えばリーク結果を出力したり、オフセットの計算結果を入力したりができません。

しかし我々は自由にコードを組むことができます。入出力のやり方はkernelのバイナリで勉強させてもらいましたので、以下のようなコードを足しましょう。ペイロードも大きいので贅沢に使います。

```python
# shellcode in kernel
def alloc(size):
    return asm('''
        xor eax, eax
        mov rdi, {}
        int 0x71
    '''.format(size))

def g2h(addr, length): # from guest to host memory write
    return asm('''
        xor eax, eax
        inc eax
        mov rdi, {}
        mov rsi, {}
        int 0x71
    '''.format(addr, length))

def h2g(addr, length): # from host to guset memory write
    return asm('''
        xor eax, eax
        inc eax
        inc eax
        mov rdi, {}
        mov rsi, {}
        int 0x71
    '''.format(addr, length))

def gout(addr, length): # guest output
    return asm('''
        mov rsi, {}
        mov cx, {}
        rep outsb 
    '''.format(addr, length))

def gin(addr, length): # guest input
    return asm('''
        mov rdi, {}
        mov cx, {}
        rep insb 
    '''.format(addr, length))

def free():
    return asm('''
        xor eax, eax
        inc eax
        inc eax
        inc eax
        int 0x71
    ''')
```

これで、例えばホストでリークした値は`h2g`でゲストメモリに持ってきて、`gout`で出力すれば良いことが分かります。入力は逆に、`gin`からの`g2h`で実現します。

またmallocについて、試してみると分かりますが、スレッドで動作するmallocであるため、main_arenaに紐付かずに動作します。要するにfreeしただけではlibcのアドレスが入手できません。  
代わりにheap上にはたくさんのポインタの跡があります。どうもunicornの何かの構造体が持っている関数ポインタの跡地のように見えます。  
何度か実行してみて、固定のオフセットを探してunicornのライブラリの位置を確定させます。  
ライブラリにはgotがあって、そこにはlibcのアドレスが記載されているので、それを拝借してきます。あとはfree_hookへsystemを入れて終了です。

任意アドレスallocはチャンクのfdを上書きするだけで済みます。隣接するチャンクを作って、一度目はunicornのgotを狙ってlibcリーク、二度目はfree_hookの上書きを行います。

![](/assets/pwnception/2020-12-09-21-46-56.png)
