# 目的  
Python-IRIS(認可サーバ、リソースサーバ)間で[認可コードフロー](https://openid-foundation-japan.github.io/rfc6749.ja.html#grant-code)を確認する。

本プログラムはWindowsで実行することを想定。

> デバッグ用の書きなぐりプログラムです :-)

# 前提  
IRIS,WebGatewayはPCからアクセス可能なLinux上のコンテナやwsl2上で動作させることを想定。

# 導入方法
0. IRISで[こちら](https://github.com/IRISMeister/iris-oauth2.git)を使用してoAuth2環境を作成

1. git clone
```
> git clone https://github.com/IRISMeister/python-oauth2-client.git
```
2. iris-oauth2.gitで作成したssl/web/all.crtをc:\tempにコピー。
```
[VM]
scp irismeister@webgw.localdomain:~/iris-oauth2/ssl/web/all.crt c:\temp\all.crt
[WSL2]
cp ssl/web/all.crt /mnt/c/temp 
```

3. iris-oauth2.gitでstart.sh実行時に表示されるjsonの内容を.\credentials.jsonにコピー。
```
[VM]
scp irismeister@webgw.localdomain:~/iris-oauth2/client/credentials_python.json c:\git\python-oauth2\credentials.json
[WSL2]
cp client/credentials_python.json /mnt/c/git/python-oauth2-client/credentials.json
```

4. ホスト名webgw.localdomainでiris-oauth2.gitが動作している環境にアクセスできるように、hostsファイルを編集

C:\Windows\System32\drivers\etc\hosts
```
192.168.11.48 webgw webgw.localdomain
```

# 実行方法
```
>python --version
Python 3.10.9
> cd python-oauth2-client
> pip install -r requirements.txt
> python request.py
```
# 謝辞
こちらのサイトを参考にさせていただきました。

https://qiita.com/hoto17296/items/2d2cb76d323099e9f8ab
https://www.camiloterevinto.com/post/oauth-pkce-flow-from-python-desktop
