# WinPcap 抓包记录与统计示例

本程序使用 WinPcap 侦听网络数据流，解析并记录：

- 时间
- 源 MAC
- 源 IP
- 目标 MAC
- 目标 IP
- 帧长度

日志输出格式（逗号分隔）示例：

```
2015-03-14 13:05:16,60-36-DD-7D-D5-21,192.168.33.1,60-36-DD-7D-D5-72,192.168.33.2,1536
```

程序还会按固定时间窗口（默认 60 秒）统计：

- 来自不同源 MAC 的通信总字节数/包数
- 来自不同源 IP 的通信总字节数/包数
- 发至不同目标 MAC 的通信总字节数/包数
- 发至不同目标 IP 的通信总字节数/包数

## 1. 依赖

- WinPcap（或兼容开发包）
- Visual Studio C++ 编译环境

确保以下头文件和库可用：

- `pcap.h`
- `wpcap.lib`
- `Packet.lib`
- `Ws2_32.lib`

## 2. 编译

在“x64 Native Tools Command Prompt for VS”中执行（按你的安装路径修改 Include/Lib 路径）：

```bat
cl /EHsc /std:c++17 main.cpp /I"C:\WpdPack\Include" /link /LIBPATH:"C:\WpdPack\Lib\x64"
```

如果你已把 WinPcap 开发包路径配置到全局环境，直接编译也可：

```bat
cl /EHsc /std:c++17 main.cpp
```

## 3. 运行

```bat
main.exe [logPath] [statsPath] [intervalSeconds] [adapterIndex]
```

参数说明：

- `logPath`：逐包日志文件，默认 `packet_log.txt`
- `statsPath`：统计输出文件，默认 `packet_stats.txt`
- `intervalSeconds`：统计周期（秒），默认 `60`
- `adapterIndex`：网卡索引，默认 `0`

示例：

```bat
main.exe packet_log.txt packet_stats.txt 60 0
```

说明：

- 程序启动会打印选中的网卡。
- 建议使用管理员权限运行。
- 结束程序后会将最后一个不足 60 秒的统计窗口也写入统计文件。
