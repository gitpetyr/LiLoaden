# LiLoaden

LiLoaden 将任意二进制文件压缩、使用 AES-GCM 加密，并生成一个可独立构建的
CMake/C++ 解码工程。主入口是 `generate_cmake_project.py`。

## 安装

```bash
python3 -m pip install -r requirements.txt
```

生成工程时必须提供 16、24 或 32 字节的 AES 密钥：

```bash
python3 generate_cmake_project.py input.bin generated-project \
  --key-hex 00112233445566778899aabbccddeeff \
  --encoder lzma-aes-ipv6
```

也可以使用原始二进制密钥文件：

```bash
python3 generate_cmake_project.py input.bin generated-project --key-file aes.key
```

输出工程依赖 CMake 3.16+、C++17、OpenSSL Crypto 和 LibLZMA：

```bash
cmake -S generated-project -B generated-project/build
cmake --build generated-project/build
generated-project/build/payload_decoder restored.bin
```

## 目录

```text
generate_cmake_project.py        命令行入口
liloaden/
  encoder/
    __init__.py                  编码器注册表和统一 encode() 入口
    lzma_aes_ipv6.py             LZMA/AES-GCM/IPv6 编码器模块
  project_generator.py          CMake 工程生成逻辑和 C++ 模板
  payload_encoder.py            流式压缩、加密及 IPv6 头文件编码
tools/
  legacy_payload_encoder.py     旧版 v1 协议工具，不参与主流程
tests/                           自动化测试
```

载荷编码器也可单独调用：

```bash
python3 -m liloaden.payload_encoder input.bin payload.h \
  --key-hex 00112233445566778899aabbccddeeff
```

运行测试：

```bash
python3 -m unittest discover -s tests
```
