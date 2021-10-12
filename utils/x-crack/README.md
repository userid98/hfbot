###########目录结构描述
├── Readme.md                   // help



├── win64（win32、linux32、linux64） //各个平台文件夹



│   ├── x-crack.py           //调用主程序



│   ├── x-crack-xxx.exe                // 爆破工具



│   ├── iplist.txt         // ip列表



│   ├── user.dic               // 用户名字典



│   ├── pass.dic              // 口令字典



###########py文件中函数功能

1. PwdCrack

   ```中文
   功能:
       对给定的ip和具体服务进行弱口令爆破，其中，若爆破第一次不成功再爆破一次，并返回爆破结果。
       输入中可指定具体用户名和口令也可不指定，每次建立ssh连接超时时间默认为10秒钟。
   input:
       ip，端口号，服务协议(, 指定用户名, 口令)
   output:
       [ip,用户名,口令]
   ```

2. insertlist

   ```
   功能:
       将爆破出的用户名和弱口令移至字典的最前面,方便下一次爆破
   input:
       需要插入的值, 字典路径
   output:
   ```

3. readflag

   ```
   功能:
   	通过登录ssh：
           判别操作系统类型
           读取flag
   input:
       ip, 用户名, 口令(, 端口号)
   output:
       flag内容
   ```