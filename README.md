# LiLoaden

LiLoaden 将任意二进制文件压缩、使用 AES-GCM 加密，并生成一个可独立构建的
CMake/C++ 解码工程。主入口是 `generate_cmake_project.py`。

当前提供两种编码器：

- `lzma-aes-ipv6`：`LZMA/XZ -> AES-GCM -> IPv6`。
- `ipv6`：直接将二进制按 16 字节分组转换为 IPv6 地址，不压缩也不加密。

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

直接生成 IPv6 地址列表工程不需要密钥参数：

```bash
python3 generate_cmake_project.py input.bin generated-project --encoder ipv6
```

输出工程依赖 CMake 3.16+、C++17、OpenSSL Crypto 和 LibLZMA：

```bash
cmake -S generated-project -B generated-project/build
cmake --build generated-project/build
generated-project/build/payload_decoder restored.bin
```

生成的 CMake 工程提供 `ENABLE_OLLVM` 选项。使用基于 OLLVM 的 Clang 配置工程：

```bash
cmake -S generated-project -B generated-project/build \
  -DCMAKE_CXX_COMPILER=/path/to/ollvm-clang++ \
  -DENABLE_OLLVM=ON
cmake --build generated-project/build
```

默认混淆参数为控制流扁平化、虚假控制流和指令替换：
`-mllvm;-fla;-mllvm;-bcf;-mllvm;-sub`。不同 OLLVM 分支的参数可能不同，
可在配置时覆盖缓存变量：

```bash
cmake -S generated-project -B generated-project/build \
  -DCMAKE_CXX_COMPILER=/path/to/ollvm-clang++ \
  -DENABLE_OLLVM=ON \
  -DOLLVM_COMPILE_OPTIONS='-mllvm;-fla'
```

## 目录

```text
generate_cmake_project.py        命令行入口
liloaden/
  encoder/
    __init__.py                  编码器协议、注册表和统一分发入口
    ipv6.py                      原始二进制与 IPv6 地址列表互转模块
    lzma_aes_ipv6.py             Python 编码与配套 C++ 解码模块
  project_generator.py          通用 CMake 工程生成逻辑
  payload_encoder.py            流式压缩、加密及 IPv6 头文件编码
tools/
  legacy_payload_encoder.py     旧版 v1 协议工具，不参与主流程
tests/                           自动化测试
```

## 编码器模块接口

每个 `liloaden/encoder/<name>.py` 模块同时维护二进制编码逻辑和对应的
C++ 内存解码代码，并实现以下标准入口：

```python
NAME: str
CLI_EPILOG: str

def add_cli_arguments(parser):
    """向通用 CLI 注册当前编码器专属参数。"""

def encode_from_cli(args, source, output, namespace) -> EncoderArtifacts:
    """解析编码器参数、执行编码并返回需要生成的附加头文件。"""

def encode(source, output, **encoder_options):
    """程序化编码入口；关键字参数由当前编码器定义。"""

def cpp_decoder(namespace) -> CppDecoder:
    """返回 header、source、cmake_packages 和 cmake_libraries。"""
```

C++ 端统一声明 `embedded::PayloadBuffer` 与以下精简接口：

```cpp
embedded::PayloadBuffer decode_payload(char*& data, std::size_t& size);
```

`data` 传出解码后内存首地址，`size` 传出有效字节数，返回的
`PayloadBuffer` 持有该内存并在析构时释放。`data` 是借用指针，仅在返回的
`PayloadBuffer` 未析构、未被移动期间有效；调用方不得单独释放。典型调用：

```cpp
char* data = nullptr;
std::size_t size = 0;
embedded::PayloadBuffer payload = embedded::decode_payload(data, size);
```

新增模块后，将模块加入 `liloaden/encoder/__init__.py` 的 `_ENCODERS` 即可供
`--encoder` 选择。`--key-hex`、`--key-file`、`--chunk-size` 等参数属于
`lzma-aes-ipv6`，由该模块动态加入帮助页；其他编码器可声明完全不同的参数。

载荷编码器也可单独调用：

```bash
python3 -m liloaden.payload_encoder input.bin payload.h \
  --key-hex 00112233445566778899aabbccddeeff
```

运行测试：

```bash
python3 -m unittest discover -s tests
```
