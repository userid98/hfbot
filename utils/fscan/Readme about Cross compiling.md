

​                                                                   **跨平台fscan扫描器使用说明**



1.首先在命令行进入到文件夹下

![1630931616617](C:\Users\DELL\AppData\Local\Temp\1630931616617.png)

2.在命令行中依次执行以下命令（以生成64位linux为例）：

​          go env -w CGO_ENABLED=0

​          go env -w GOOS=linux 

​          go env -w GOARCH=amd64  （若是32位，则令GOARCH=386）

​          go build -ldflags="-s -w " -trimpath

![1630931007864](C:\Users\DELL\AppData\Local\Temp\1630931007864.png)

![1630932039664](C:\Users\DELL\AppData\Local\Temp\1630932039664.png)



3.执行该命令后，windows系统生成fscan.exe，linux系统生成fscan，然后根据fscan-main中的Readme.md进行相关的扫描。

![1630932068446](C:\Users\DELL\AppData\Local\Temp\1630932068446.png)

![1630932095693](C:\Users\DELL\AppData\Local\Temp\1630932095693.png)