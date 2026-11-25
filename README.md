# Audi MHI2 CN P0916 原生无线 CarPlay 研究展示

[English](README_EN.md) | **简体中文**

本项目旨在探索奥迪经典 **MHI2（`MHI2_CN_AU37x_P0916` / MU0916，QNX 6.5 ARM32）** 车机平台上，在不修改或刷写原厂 Flash 分区的前提下，复用车载蓝牙、车载 Wi‑Fi 热点与原厂 `libairplay.so (210.81)` 实现**纯内存原生无线 Apple CarPlay**，并完整保留有线 USB CarPlay 通路。

> [!WARNING]
> **版权与严禁商业化声明**
>
> 本项目全部原创研究成果、文档与代码版权均归作者（**GitHub: `@emotional-lau` / 微博・汽车之家: `@emotional_lau`**）所有，保留一切权利。
>
> **严禁任何未经本人书面授权的商业化行为**（包括但不限于倒卖源码或二进制包、打包售卖、收费代安装/刷机、集成至商用工具箱或盈利性二次分发）。个人仅限在保留本声明的前提下用于非商业性的技术交流与学习。详见 [LICENSE](LICENSE)。

---

> [!IMPORTANT]
> **公开仓库边界说明（研究展示窗）**
>
> - **目前为非完全的阶段性研发进度展示，仅供技术交流与学习研究使用。**
> - 为有效防止被直接复刻或包装倒卖，**本公开仓库仅提供研究文档、系统架构说明以及通用无固件依赖的纯 C 密码学基础库（`src/crypto/`）**。
> - 所有与目标车机绑定的核心实现——包括但不限于原厂 `libairplay.so` / `dio_manager` 内存对象布局与固定地址、运行时 Hook 逻辑、HAP 配对/控制会话状态机、无线音频中继、蓝牙 iAP2 / RFCOMM 集成、离线构建与二进制嫁接工具链、以及实车部署框架——**均在私有仓库中维护，不在此公开仓库分发**。

---

## 一、总体架构思路（概念示意图）

在不改写车机原厂系统分区的前提下，整套方案的核心思路完全围绕**纯内存拦截与原厂组件复用**展开：

```mermaid
flowchart LR
    iPhone["iPhone (iOS CarPlay)"] <-->|"蓝牙 RFCOMM (iAP2 鉴权与 Wi-Fi 交接)"| BTHook["车载蓝牙服务扩展层"]
    iPhone <-->|"Wi-Fi Control / Event (HAP + ChaCha20)"| AirPlayHook["原厂 AirPlay 210.81 运行时扩展层"]
    iPhone -->|"H.264 视频流 / AAC-LC & Opus 音频流"| AirPlayHook
    BTHook -->|"拉起与会话触发"| SI["系统集成管理层 (SI / DIO)"]
    AirPlayHook -->|"解密并转为原厂 PCM / 裸帧"| StockMMI["原厂显示与 nvaudio 音频通路"]
    StockMMI -->|"MMI 旋钮 / 屏幕 / 车载音响"| User["实车交互输出"]
```

---

## 二、当前实车验证进度（2026-11-25）

- **已实车点亮并验证通过的部分**：
  - 蓝牙 iAP2 鉴权与车载 Wi‑Fi 凭据无线交接、CarPlay 控制会话自动发现、HAP 加密控制与事件通道建立；
  - `800×480` H.264 主屏幕画面点亮、MMI 旋钮交互，以及连接管理器手动断开/重连与自动回连稳定性；
  - **无线全路音频已实现零卡顿实车通过**：媒体音乐（48 kHz AAC-LC，针对 iOS 突发发包特性完成预填充与抖动缓冲适配，实测零欠载 `underruns=0`）、导航提示音（Opus 16 kHz）以及双向通话/Siri 语音通道（Opus 16 kHz）；
  - **零 Flash 配对持久化与蓝牙交接释放**：冷启动可跳过首次配对直通快速校验，进入无线会话后可优雅释放经典蓝牙链路。
- **下一阶段收尾待完善部分（非完整版）**：
  - **SIM 卡未插入提示抑制**：已定位客户端接入计数触发链并完成纯内存零 Flash 抑制方案设计，待上车验证；
  - **奥迪虚拟座舱（Virtual Cockpit）支持**：包括兼容既有仪表地图投屏补丁与补充仪表盘无线 CarPlay 曲目信息显示；
  - **日常运行模式与最终边界回归**：免单次触发开关、日志轮转，以及 Siri/车载麦克风/来去电切换、有线 CarPlay 与原厂蓝牙音频零回归验收。

## 三、本公开仓库目录说明

本公开仓库仅保留通用 C 密码学基础实现与 QNX 基础 ABI 类型头（共 3 个文件），**无任何目标固件偏移或车机进程 Hook 代码**：

| 文件 | 说明 |
| --- | --- |
| `src/crypto/wcp_crypto.h` / `wcp_crypto.c` | 纯 C 实现的通用密码学原语（SRP-6a、X25519、Ed25519、SHA-512、HKDF-SHA-512、ChaCha20-Poly1305） |
| `src/crypto/qnx65_abi.h` | QNX 6.5 基础数据结构与 POSIX/Socket 常量声明 |

---

## 四、参考项目与致谢

本项目在前期协议分析与技术架构调研过程中主要参考了以下 4 个开源项目（已分别注明具体参考方向）：

1. **[joeyQuery/MHI2-wirelessCarPlay](https://github.com/joeyQuery/MHI2-wirelessCarPlay)**
   - **参考内容**：经典 MHI2 平台的蓝牙 iAP2 / DIO / AirPlay 边界追踪分析与固件对照研究记录。

2. **[korhojoa/mib2-extenders](https://github.com/korhojoa/mib2-extenders)**
   - **参考内容**：MIB2 High（QNX）平台蓝牙服务生命周期管理、Wi‑Fi 热点接入与系统扩展架构实践。

3. **[luka-dev/mib2q-carplay-rgi](https://github.com/luka-dev/mib2q-carplay-rgi)**
   - **参考内容**：无线 CarPlay 完整协议阶段设计（iAP2 认证与 Wi‑Fi 交接参数、Bonjour 控制发现与连接触发、系统集成管理器架构，以及原厂 AirPlay `210.81` 的配对与流媒体交互边界）。

4. **[congobg/MHI2Q_WiFi_CarPlay](https://github.com/congobg/MHI2Q_WiFi_CarPlay)**
   - **参考内容**：基于原厂 `libairplay.so (210.81)` 的无线音频中继思路（无线 `/info` 音频能力声明、媒体流类型兼容映射、UDP 解码并结合原厂抖动缓冲播放进度限速回喂 PCM，以及麦克风上行编码方案）。

---

## 五、免责声明

- 本仓库仅供车载电子系统、QNX 架构及无线 CarPlay 协议的**个人学习与技术研究交流**，不提供成品刷机包或商业方案。
- 版权归作者（GitHub: `@emotional-lau` / 微博・汽车之家: `@emotional_lau`）所有，禁止一切未经授权的商业化与倒卖行为。详见 [LICENSE](LICENSE)。
