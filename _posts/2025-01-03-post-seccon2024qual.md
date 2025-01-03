---
layout: page
title: "SECCON CTF 2024"
date: 2025-01-03 00:00:00 -0000
---

忘れないうちに書き残しておきます。

# Paragraph

23文字のFSBでスタックに書き込めます。no-pieです。

```c
include <stdio.h>

int main() {
  char name[24];
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);

  printf("\"What is your name?\", the black cat asked.\n");
  scanf("%23s", name);
  printf(name);
  printf(" answered, a bit confused.\n\"Welcome to SECCON,\" the cat greeted %s warmly.\n", name);

  return 0;
}
```

書き込み先は迷いましたが、GOTのprintfをscanfに書き換えると、スタックに書き込むことができるようになり、 以降はFSBがなくても２周目も問題なく書けるようになります。

# Baby QEMU

オフセットの範囲チェックがないため、ホストのヒープに無制限に読み書きできます。基本的にはやるだけです。

```c
static uint64_t pci_babydev_mmio_read(void *opaque, hwaddr addr, unsigned size) {
        PCIBabyDevState *ms = opaque;
        struct PCIBabyDevReg *reg = ms->reg_mmio;

        debug_printf("addr:%lx, size:%d\n", addr, size);

        switch(addr){
                case MMIO_GET_DATA:
                        debug_printf("get_data (%p)\n", &ms->buffer[reg->offset]);
                        return *(uint64_t*)&ms->buffer[reg->offset];
        }

        return -1;
}

static void pci_babydev_mmio_write(void *opaque, hwaddr addr, uint64_t val, unsigned size) {
        PCIBabyDevState *ms = opaque;
        struct PCIBabyDevReg *reg = ms->reg_mmio;

        debug_printf("addr:%lx, size:%d, val:%lx\n", addr, size, val);

        switch(addr){
                case MMIO_SET_OFFSET:
                        reg->offset = val;
                        break;
                case MMIO_SET_OFFSET+4:
                        reg->offset |= val << 32;
                        break;
                case MMIO_SET_DATA:
                        debug_printf("set_data (%p)\n", &ms->buffer[reg->offset]);
                        *(uint64_t*)&ms->buffer[reg->offset] = (val & ((1UL << size*8) - 1)) | (*(uint64_t*)&ms->buffer[reg->offset] & ~((1UL << size*8) - 1));
                        break;
        }
}
```

mmioのハンドラがvtableにまとまっているので、ヒープに偽テーブルを作って差し替えてあげれば良いです。普通にシェルを立ち上げても、出力がこっちを向かなかったので、リバースシェルにしました。またエクスプロイトを送っているとタイムアウトで終わるので、これもwgetを使って送り込みました。

# Make ROP great again
解けなかったです。raxかrdiがコントロールできるとリークができて終わるのですが、うまく調整する方法がわかりませんでした。

２つ解法があります。
1. getsを利用する方法
2. raxをうまいこと作り出す方法

## 1. getsを利用する方法
getsから出てきたときにrdiに入っているロック用の変数`_IO_stdfile_0_lock`を使ってリークする方法です。ネタもとは[こちら](https://sashactf.gitbook.io/pwn-notes/pwn/rop-2.34+/ret2gets)。想定シーンはgetsとputsが連続で何回か呼べて、リークがほしいときです。

`_IO_stdfile_0_lock`はgetsを使うときのロックを管理している変数です。構造体の後ろにTLSへのアドレスがあり、先頭4バイトがゼロで、かつTLSへのアドレスを壊すと、もとに戻してくれるという嬉しい謎機能があります。これを利用すると、getsを利用しているにもかかわらず文字列がつながってリークすることになります。

詳しくはネタもとに譲るとして、ここでは手順と仕組みを簡単にまとめておきます。

手順は以下のとおりです。

1. gets: send `p32(0)+b'aaaa'`
2. gets: send `b'aaaa'`
3. puts: leak TLS address

以降は仕組みの説明です。

まずロックの構造体が以下のとおりです。`owner`にTLSのアドレスが入ります。現在の多くの環境でglibcに隣接しているので、これがリークするとライブラリのオフセットが手に入ります。

```c
typedef struct {
    int lock;
    int cnt;
    void *owner;
} _IO_lock_t;
```

次にロックの実装です。

以下はIDAから持ってきた、`Ubuntu GLIBC 2.39-0ubuntu8.3`のgetsの、処理の前後のロックの実装です。

```c
_BYTE *__fastcall gets(_BYTE *a1)
{
    
...
    
    lock = ::stdin->_lock;
    __self = __readfsqword(0x10u);
    owner = lock->owner;
    if ( !_libc_single_threaded_internal[0] || owner )
    {
      if ( (void *)__self != owner )
      {
        if ( _InterlockedCompareExchange(&lock->lock, 1, 0) )
          _GI___lll_lock_wait_private(&lock->lock);
        stdin_ = ::stdin;
        stdin->_lock->owner = (void *)__self;
        IO_read_ptr = stdin_->_IO_read_ptr;
        if ( IO_read_ptr < stdin_->_IO_read_end )
          goto LABEL_3;
LABEL_16:
        v5 = _GI___uflow(stdin_);
        if ( v5 == -1 )
          goto LABEL_17;
        goto LABEL_4;
      }
      ++lock->cnt;
    }
    else
    {
      lock->lock = 1;
      lock->owner = (void *)__self;
    }

...

  lock_ = stdin->_lock;
  cnt = lock_->cnt;
  if ( _libc_single_threaded_internal[0] )
  {
    if ( !cnt )
    {
      lock_->owner = 0LL;
      lock_->lock = 0;
      return result;
    }
LABEL_21:
    lock_->cnt = cnt - 1;
    return result;
  }
```

挙動をまとめると以下のとおりです。

- gets呼び出し時： `owner`が`__self`（今のTLS）と一致するか
  - 一致しない：ロックがゼロか確認してロックして、`owner`に`__self`を代入する
  - 一致する：`cnt`に1足す
- gets終了時： `cnt`がゼロか
  - `cnt`がゼロ：`lock = 0;owner = 0`
  - `cnt`が非ゼロ：`cnt`から1引く

これで意図通り実装できているのかは大いに疑問が残るところですが、紹介した手順で入力していくと以下のようにメモリ状態が遷移して、TLSのアドレスがnullなしで繋がります。（getsは入力の最後にnullが入ります。）

1. send `p32(0)+'aaaa'`
  - getsのロック処理の後：`lock = 1, cnt = 0, owner = __self`
  - 入力を受けた後：`lock = 0, cnt = 0x61616161, owner != __self`
  - getsのアンロック処理の後：`lock = 0, cnt = 0x61616160, owner != __self`
2. send `aaaa`
  - getsのロック処理の後：`lock = 1, cnt = 0x61616160, owner = __self`
  - 入力を受けた後：`lock = 0x61616161, cnt = 0x61616100, owner = __self`
  - getsのアンロック処理の後：：`lock = 0x61616161, cnt = 0x616160ff, owner = __self`

また次のgetsは、`owner == __self`が真なので、`lock`も`cnt`も何でもよいため、ロックされずに書き込めます。当然リークを得られた後なのでここに書く必要はなく、普通にROPすればよいです。

## 2. raxを作り出す方法
putsの戻り値を使ってraxをコントロールすることで、jmp raxにつなぐという方針です。これができる時点でrdiコントロールできているだろうと思ったので早々に思考からは切り離していましたが、方法１でも見たとおりrdiはrwを向いているため、文字を書いて表示すれば良いです。

ただしロックは１．で書いたとおり、`owner != __self`の状態で`lock`が非ゼロになるときは入力が吸い込まれて進めなくなります。`0x004010ea: add dil, dil; loopne 0x401155; nop; ret;`を使ってrdiを少しずらし、`0x00401157: add eax, 0x2ecb; add [rbp-0x3d], ebx; nop; ret;`と`0x00401129: mov edi, 0x404010; jmp rax;`を組みあせてraxをputsにしてリークします。

# free-free free
素直なヒープの問題でした。

データ構造が以下の通りです。先頭にポインタ、バッファのサイズが未定ですが、`len`がそこに対応します。

```c
typedef struct Data {
        struct Data *next;
        uint32_t len;
        uint32_t id;
        char buf[];
} data_t;
```

`Data`は１６バイトなので、`alloc`は確保時のサイズを誤っていて、８バイトオーバーフローしています。また、`p->next`は初期化されていません。リストの個数は管理されていないので、最初からポインタが入っていた場合は、そこも参照されます。

```c
static int alloc(uint32_t size){
        if(size < 0x20 || size > 0x400){
                puts("Invalid size");
                return 0;
        }

        data_t *p = malloc(8+size);
        if(!p){
                puts("Allocation error");
                return 0;
        }

        p->len = size;
        p->id = rand();

        tail->next = p;
        tail = p;

        return p->id;
}
```

`edit`は`p->len`の長さをチェックすることなく、そのまま編集することができます。

```c
static int edit(uint32_t id){
        data_t *p = head.next;
        for(int i = 0; p && i < MAX_DEPTH; p = p->next, i++)
                if(p->id == id){
                        printf("data(%u): ", p->len);
                        getnline(p->buf, p->len);
                        return 0;
                }

        return -1;
}
```

バイナリ全体を通してfreeがないというのが特徴で、これによって上のバグは一見ほぼ影響ないように見えますが、topチャンクが壊せるので話が変わります。
topチャンクは、そのヘッダを壊して、大きなサイズをmallocすることで、余ったtopチャンクをfreeするテクニックが知られています。これを利用します。具体的には、例えばtopチャンクのヘッダが0x20141だった場合、これを0x141にしたあと0x200のサイズでmallocすればfreeされます。

同じサイズで8回freeを繰り返すと、最後のチャンクはunsortedbinにつながるため、今度はこのチャンクを確保します。注意として、`edit`は4回までしかリストを辿れないので、基本的にはこまめに`release`を撃っておきます。

unsortedbinにつながったチャンクを`head`につなぐと、main_arenaが有効なチャンク扱いになります。何が嬉しいかというと、`p->len`と`p->id`もmain_arenaのアドレスが利用されます。上位の2バイトが`id`です。つまり、`edit`を使って`id`を0x7000から0x8000で探索することで、有効な`id`が1つだけ見つかります。また編集できるときにはサイズも出るので、これによってlibcアドレスがリークします。

あとは、main_arenaより高位のアドレスに使えそうなデータがないかを見ると、stderrがありますので、FSOPペイロードをいれておしまいです。途中、入力で使っているポインタがあるため、これらは保持しておく必要があります。

# TOY/2

１６ビットの処理系を模したvm問です。競技期間終了後、１５分遅れで解けました。悲しい。

１命令は２バイトで固定されていて、最初の１２ビットが`addr`, 残りの４ビットが`op`として処理されます。

`addr`を受けて読み書きする命令は問題なさそうですが、レジスタ参照でアクセスする命令たちが良くないです。Aレジスタを使って１６ビットをすべて使ってオフセットを指定できるため、`_data`より高位アドレスの読み書きができます。

```c
      case 12: /* LDI */
        _regs.a = mem_read(_regs.a & (size() - 1));
        break;

      case 13: /* STT */
        mem_write(_regs.a & (size() - 1), _regs.t);
        break;
```


```c
  inline uint16_t size() {
    return _mem.size();
  }
```


高位アドレスには何があるのかというと、`_mem`のアドレスと長さ、あとはレジスタが並んでいます。とりあえず長さを壊しておけば良さそうです。

```c
private:
  std::array<uint8_t, MEM_SIZE> _data;
  std::span<uint8_t> _mem;
  struct {
    Reg pc;
    Reg a;
    Reg t;
    bool c;
    bool z;
  } _regs;
};
```

というわけで、まずは`_mem`のアドレスの低位１バイトを書き換えて高位側にずらします。そのうえで、長さを伸ばします。あとはヒープを適当に読み書きすればいいやと気楽に思っていたのですが、ライブラリアドレスが、このvmでアクセスできる範囲にはありません。vtableからバイナリのアドレスは判明しますが、ここにはシェルを立ち上げる材料が足りていませんでした。
またもう１つ大きな課題としては、`_mem`をずらしてもpcが追随しないため、ずらした先に命令が置かれていないとうまく動きません。これが理由で、`_mem`を大きく動かしたり、一時的に読めないアドレスに動かすことはできません。

途方に暮れて、色々動かしていたところ、たまたまcatchに入ったあとでヒープにstdc++のポインタがいくつか入っていることに気づきます。これはつまりcatchさせた後も実行できれば、範囲外読み取りでアドレスを持ってくることができます。

コード実行についてはvirtual関数の`vm->dump_registers`が実行終了時に呼ばれるため、vtableを差し替えて呼ばせれば、再び`vm->run`に戻れます。１回目とは違う命令を実行したいので、もう一度コードの入力からやりたいですが、これはmallocを挟まないとカウンタがリセットされずできません。つまり、上手く`_mem`をずらして１回目に通らなかったコードから実行するか、メモリの値を書き換えて、条件ジャンプで分岐する必要があります。

２回めの処理に入れたら後は簡単で、範囲外読み取りをしてstdc++のポインタを持ってきて、必要なライブラリのガジェットのアドレスに変えていけば良いです。

終了時の注意点は、１回目同様にcatchからは飛べないことです。途中でスタックがアラインしていないので止まります。正常に終了させて、`vm->dump_registers`に行くことでsystemを呼ぶことができます。正常に終了させるためには、`for (size_t i = 0; i < MAX_RUN && _regs.pc < size(); i++) {`をfalseにすれば良いので、pcを大きな値にすれば良いです。

まとめると以下の手順でスクリプトを作ります。

1. `_mem`を高位側に１６バイトずらす（長さを書き換えるため）
2. 長さを書き換えて、`_mem`のアドレスをコピー
3. `_mem`を低位側に２４バイトずらす（vtableを差し替えるため）
4. fake vtableを作って、vtableを差し替える
5. 再び`_mem`を高位側に１６バイトずらして（２周目の処理に飛ばすため）、`illegal`を呼び、stdc++のポインタを呼び込む
6. 範囲外読み込みを使ってstdc++のポインタを持ってきて、fake vtableを書き換える
7. 準備ができたらpcを0xffffに設定し、正常に`vm->run`を抜ける

# 取り組み時間と反省
- 15時-17時過ぎ（2時間半）：paragraph。多少困った。
- 17時半−22時半（5時間）：babyqemu。ソース見た瞬間やるだけを理解したが、実装でもたついた。
- 23時-24時（1時間）：mrga。rdiかraxの調整が鍵だがスッと使えるのが見つからない。1時間で次に行った。非自明だったので正解ではあった。
- 24時-翌日3時（3時間）：free-free-free。サイズが微妙にバグってるパターンで、未初期化見つけてからはすんなり行った。妥当な時間か。
- 3時-14時過ぎ（11時間半）：toy2。ソースありなのでほぼ解析作業はなかったが、`_mem`を何回かずらす方針にするか、リークするものが何もないところで偶然catchでライブラリアドレスが出てくるのを発見、2回目の入力ができるか、2回目のvtable参照をどうさせるか辺りの方針で2転3転、また実装でも引き算の順序が逆になっててあわなかったり、`_mem`をずらした時に`pc`もズレるので、そこを上手く受けられるように試行錯誤したり、BNEが思い通りに動かなかったり、最後copでスタックアラインしなかったのでガジェット差し替えが必要で最後まで見通しが立たなかった。

今回は24時間なので寝ずにやろうとして、前日の睡眠時間を伸ばしました。結論ここに関しては少し寝たほうが良さそうに思いました。（TOY2がこんなにかかっているとは思わなかったし、なんなら間に合わなかったので、恐らく脳が動いていない。）
両日ともほぼ外出していたので正確な作業時間はわからないものの、12時間くらいで一度手を止めるのが良いのかなと思っています。

TOY/2（というかこれ系のVM問、例としてhitcon2023のsubleq問など）は、エクスプロイトがぐちゃぐちゃになりがちで、それは上手く手続きの関数化ができていないことが原因なので、そろそろ慣れたいなと感じています。今回は`_mem`をずらすところで方針がしっかり固まらないまま最後まで行ったのでちょっとそれでたたみきる自信がなかったのもまた事実ですが、そちらは解決する前提で。

結局は知っている手順を正しく実行し、その上で自分の知らない発見的な要素をあぶり出すのに時間を使い、手戻りを減らすべくエクスプロイトをきれいに書いていくというあまりにも当たり前の結論になりました。

今年は無駄に詰まったところもなくいい感じに進められた一方で、仮にpwnが全部埋まっても予選を抜けられなかったため、さっさと片付けてさらに別の問題に取り組む必要がありました。

早くたたむ意識を持って続けて行こうと思います。

