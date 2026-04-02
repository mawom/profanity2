# profanity2

GPU 加速的以太坊靓号地址生成器。单文件，零依赖。

基于 [1inch/profanity2](https://github.com/1inch/profanity2) 改进 — 内置密钥生成、`--prefix`/`--suffix` 快捷参数、OpenCL 内核嵌入二进制，整个工具就是一个可执行文件。

## 用法

```bash
./profanity2 --prefix dead                    # 地址以 0xdead 开头
./profanity2 --suffix beef                    # 地址以 beef 结尾
./profanity2 --prefix dead --suffix beef      # 同时指定前缀和后缀
./profanity2 --prefix dead --contract         # 匹配合约地址
./profanity2 --benchmark                      # 测试 GPU 速度
```

输出的私钥可以直接导入任何钱包，无需额外计算。

## 下载

预编译二进制：[Releases](../../releases)

- `profanity2-macos-arm64` — macOS (Apple Silicon)
- `profanity2-linux-x64`
- `profanity2-windows-x64`

## 编译

```bash
# macOS
make

# Linux
sudo apt-get install -y ocl-icd-opencl-dev && make

# Windows (MSVC + vcpkg)
vcpkg install opencl:x64-windows
cl /std:c++14 /O2 /EHsc /I<opencl_include> Dispatcher.cpp Mode.cpp precomp.cpp profanity.cpp SpeedSample.cpp /Fe:profanity2.exe /link /LIBPATH:<opencl_lib> OpenCL.lib
```

## 与上游的区别

| 特性 | 上游 1inch/profanity2 | 本 fork |
|------|----------------------|---------|
| 密钥生成 | 需手动 openssl + 计算 | 内置，自动完成 |
| 私钥输出 | 部分密钥（需手动相加） | 最终私钥，直接可用 |
| 模式匹配 | `--matching deadXXXX...`（补齐 40 字符） | `--prefix dead --suffix beef` |
| .cl 内核文件 | 运行时需要 | 嵌入二进制 |
| 部署 | 二进制 + 2 个 .cl 文件 | 单个二进制 |

## 工作原理

1. 内部随机生成 secp256k1 密钥对
2. 将公钥传给 GPU 搜索引擎
3. GPU 搜索匹配目标模式的靓号地址
4. 自动计算最终私钥：`seed_key + partial_key mod n`
5. 输出可直接使用的私钥和地址

**设计即安全** — GPU 只能看到公钥，永远接触不到私钥。

## 性能

| GPU | 速度 |
|-----|------|
| Apple M4 | ~100 MH/s |
| RTX 4090 | ~1000+ MH/s |
| RTX 3060 | ~300 MH/s |

| 模式长度 | 预估时间 @ 100 MH/s |
|---------|---------------------|
| 4 字符 | < 1 秒 |
| 6 字符 | ~2 秒 |
| 8 字符 | ~40 秒 |
| 10 字符 | ~3 小时 |

前缀 + 后缀的总长度决定难度。例如 3 字符前缀 + 3 字符后缀 = 6 字符，约 2 秒。

## 进阶用法

所有上游参数仍可使用：

```bash
# 原始手动模式（提供公钥）
./profanity2 -z <128位hex公钥> --matching deadXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXbeef

# 评分模式
./profanity2 --zeros          # 最多零
./profanity2 --letters        # 最多字母
./profanity2 --mirror         # 镜像

# 调优
./profanity2 --prefix dead -I 256    # 更快初始化，较低吞吐
./profanity2 --prefix dead -n        # 跳过 OpenCL 缓存
```

## 安全说明

- 基于 profanity2 的「设计即安全」架构
- 私钥永远不暴露给 GPU
- 使用系统级密码学随机数生成器
- OpenCL 内核嵌入二进制，无需外部文件

## 致谢

- [profanity](https://github.com/johguse/profanity) — Johan Gustafsson
- [profanity2](https://github.com/1inch/profanity2) — 1inch Network
