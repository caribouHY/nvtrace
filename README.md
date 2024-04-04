# nvtrace

IPアクセスルータSi-R GシリーズでキャプチャしたISAKMPパケットデータをWireshark等で表示可能なpcapファイルに変換するアプリケーション。

## ビルド方法

環境
- Windows11
- Go 1.20

PowerShell上で下記コマンドを実行
```
git clone https://github.com/caribouHY/nvtrace.git
cd nvrace
go build .
```
`nvtrace.exe`が生成される

## 使い方

Si-RルーターCLI上で`show tace ike`コマンドを実行し、出力結果をテキストファイルにコピペする。
```
Router# show trace ike
[1]  ISAKMP Receive(After Decrypt)		Dec 5 15:01:46 2023
        Local  Address:(192.168.1.1)
        Remote Address:(192.168.2.2)
        Cookies:(0e965c548998dd9d:967fc4fdabca3b65)
        Exchange Type: Informational              Len:140(0x8c)
        data=0e96 5c54 8998 dd9d 967f c4fd abca 3b65 
             0810 0501 2686 9ba0 0000 008c 0b00 0024 
             9906 c878 07d7 c627 392c 7610 030a 8b37 
             c5b4 88ae e0a7 92db 9644 7bfa 833b 079a 
             0000 0042 0000 0001 0304 000e 0df7 e674 
...(省略)
```

`nvtrace.exe`にテキストファイルをドラッグ＆ドロップすると、テキストファイルと同じディレクトリにpcapファイルが生成される。


