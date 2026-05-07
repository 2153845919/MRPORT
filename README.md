# MRPORT-过检测

基于 WinDivert 的透明代理工具，功能与 Proxifier 一致。
将指定域名的流量代理到 SOCKS5 服务器，其余直连。

## 功能

- 代理 `cschannel.anticheatexpert.com`（任意端口）→ SOCKS5
- 代理 `127.0.0.1:80` → SOCKS5
- SOCKS5 用户名密码认证
- 延迟检测（端口 10012）
- 远程公告读取（有道云笔记）
- 双进程守护
- 掉线自动杀 `nrc_launcher.exe`
- 配置持久化

## 构建

```bash
# Linux/macOS (需要 .NET 8 SDK)
chmod +x download-windivert.sh build.sh
./build.sh

# Windows PowerShell
.\build.ps1
```

## 依赖

- .NET 8 SDK
- WinDivert v2.2.0（自动下载）
- Windows 10/11 x64（管理员权限运行）

## 首次使用

1. 运行软件（自动请求管理员权限）
2. 输入 SOCKS5 账号密码，点击保存
3. 点击启动
4. WinDivert 驱动会自动安装（如果首次使用）

## WinDivert 驱动安装

首次运行需要安装驱动。软件启动时会自动尝试安装，也可手动：
```
WinDivert64.exe install
```

## 目录结构

```
MRPORT/
├── MRPORT.csproj
├── app.manifest          # 管理员权限声明
├── Styles.xaml           # UI 主题样式
├── App.xaml / .cs        # 应用入口
├── MainWindow.xaml / .cs # 主窗口
├── Models/
│   └── AppConfig.cs      # 配置模型
├── Services/
│   ├── ConfigManager.cs      # 配置读写
│   ├── LogService.cs         # 日志服务
│   ├── AnnouncementService.cs# 远程公告
│   ├── Socks5Client.cs       # SOCKS5 客户端
│   ├── PacketCapture.cs      # WinDivert 抓包
│   ├── LocalProxyServer.cs   # 本地透明代理
│   ├── ProxyEngine.cs        # 主引擎
│   ├── LatencyMonitor.cs     # 延迟检测
│   └── ProcessGuard.cs       # 进程守护
├── WinDivert/            # WinDivert 原生 DLL
├── build.sh              # 构建脚本 (Linux/macOS)
└── download-windivert.sh # WinDivert 下载
```
