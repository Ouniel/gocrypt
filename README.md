# 🔐 GoCrypt 全能密码加解密工具

<p align="center"> <img alt="Go版本" src="https://img.shields.io/badge/Go-1.20%2B-blue"> <img alt="多平台支持" src="https://www.google.com/search?q=https://img.shields.io/badge/%E5%B9%B3%E5%8F%B0-Windows%252FLinux%252FmacOS-green"> <img alt="开源协议" src="https://img.shields.io/badge/许可-Apache-orange"> </p>

> 专为 CTF 选手和安全研究人员打造的瑞士军刀级密码工具，集成了数十种古典密码、现代编码及哈希破解功能。

GoCrypt 是一个基于 Go 语言编写的高性能命令行密码工具。它不仅支持常见哈希算法的计算与并发字典爆破，还内置了 CTF 竞赛中常见的 20 余种编码和加密算法（如摩斯、猪圈、当铺密码等），支持一键加解密与参数调整。

## ✨ 核心功能

- **⚡ 哈希计算与爆破**：
  - 支持 MD5, SHA1/256/512, MySQL, NTLM, MSSQL, Linux Crypt ($1$, $5$, $6$), Bcrypt 等。
  - 支持加盐哈希（Salted Hash）计算与破解。
  - 自动识别哈希类型，多线程并发字典爆破。
- **🧩 CTF 古典/现代密码**：
  - **位移/替换类**：凯撒 (Caesar), ROT13, Atbash, 维吉尼亚 (Vigenere), 仿射 (Affine), 栅栏 (Fence)。
  - **编码类**：Base64, Base91, 摩斯 (Morse), 01摩斯, 培根 (Bacon)。
  - **符号/图形类**：猪圈 (Pigpen), 银河字母 (Galaxy), 象形文字 (Hieroglyph), 核心价值观编码, 当铺密码 (Dangpu)。
  - **键盘类**：手机键盘 (Phone Keypad), 键盘坐标 (Keyboard Grid)。
  - **脑洞类**：Brainfuck, Ook。
  - **文件类**：ZIP 伪加密修复与生成。
- **🛠️ 灵活易用**：
  - 统一的命令行接口，模式清晰 (`hash-enc`, `hash-crack`, `ctf`)。
  - 智能参数处理，支持文件路径输入。

## 🚀 快速开始

### 安装步骤

```
# 克隆仓库
git clone [https://github.com/your-repo/gocrypt.git](https://github.com/your-repo/gocrypt.git)

# 进入项目目录
cd gocrypt

# 下载依赖
go mod tidy

# 直接运行
go run main.go -h

# 或编译为二进制文件
go build -o gocrypt
```

## 🛠️ 参数详解

### 全局模式参数 (`-mode`)

| 模式         | 说明                                            |
| ------------ | ----------------------------------------------- |
| `hash-enc`   | **哈希计算模式**：计算文本的各类哈希值          |
| `hash-crack` | **哈希爆破模式**：对哈希值进行字典攻击          |
| `ctf`        | **CTF工具模式**：进行各类编码和加密算法的加解密 |

### 通用选项

| 参数    | 说明                  | 示例               |
| ------- | --------------------- | ------------------ |
| `-text` | 输入文本或密文 (必填) | `-text "hello"`    |
| `-salt` | 盐值 (用于加盐哈希)   | `-salt "mysalt"`   |
| `-dict` | 字典路径 (仅爆破模式) | `-dict "pass.txt"` |
| `-t`    | 爆破线程数            | `-t 16`            |

### CTF 模式专用选项

| 参数       | 说明                                           | 示例                  |
| ---------- | ---------------------------------------------- | --------------------- |
| `-algo`    | 指定算法名称                                   | `-algo caesar`        |
| `-op`      | 操作类型: `enc`(加密/编码) 或 `dec`(解密/解码) | `-op dec`             |
| `-shift`   | 偏移量 (凯撒)                                  | `-shift 3`            |
| `-key`     | 密钥 (维吉尼亚) 或 栏数 (栅栏)                 | `-key "SECRET"`       |
| `-a`, `-b` | 仿射密码参数 ($y = ax + b$)                    | `-a 5 -b 8`           |
| `-out`     | 输出文件路径 (仅用于 ZIP 算法)                 | `-out flag_fixed.zip` |

## 📊 使用示例

以下展示了所有支持算法的使用方法。

### 1. 哈希计算与爆破 (`hash-enc` / `hash-crack`)

**计算哈希：**

一次性计算输入文本的所有支持哈希值（包含 MD5, SHA家族, NTLM, MySQL, Bcrypt 等）。

```
# 计算字符串 "123456" 的所有支持哈希值
./gocrypt -mode hash-enc -text "123456"

# 计算加盐 MD5 ($pass.$salt)
./gocrypt -mode hash-enc -text "123456" -salt "admin"
```

**爆破哈希：**

支持自动识别哈希算法类型，无需手动指定算法。

```
# 1. 常见哈希 (MD5, SHA1/256/512)
./gocrypt -mode hash-crack -text "e10adc3949ba59abbe56e057f20f883e" -dict pass.txt

# 2. Windows NTLM 哈希
./gocrypt -mode hash-crack -text "32ed87bdb5fdc5e9cba88547376818d4" -dict pass.txt

# 3. MySQL 数据库哈希 (Old & New)
./gocrypt -mode hash-crack -text "6bb4837eb74329105ee4568dda7dc67ed2ca2ad9" -dict pass.txt

# 4. Linux Shadow 哈希 ($1$, $5$, $6$) - 自动提取 Salt
./gocrypt -mode hash-crack -text "$6$salt$..." -dict pass.txt

# 5. Bcrypt 哈希 ($2a$, $2b$, $2y$) - 自动提取 Cost 和 Salt
./gocrypt -mode hash-crack -text "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy" -dict pass.txt

# 6. MSSQL 2012+ 哈希 (自动提取 Salt)
./gocrypt -mode hash-crack -text "0x0100abbe56e0c3044aa39d5a976f13b5333a2319aef87d7801a8" -dict pass.txt
```

### 2. CTF 算法大全 (`-mode ctf`)

#### 基础编码与位移

```
# 凯撒密码 (Caesar) - 偏移量 3
./gocrypt -mode ctf -algo caesar -op enc -text "hello" -shift 3
./gocrypt -mode ctf -algo caesar -op dec -text "khoor" -shift 3

# ROT13 (固定偏移 13)
./gocrypt -mode ctf -algo rot13 -op enc -text "hello"

# 埃特巴什码 (Atbash) - 字母倒序
./gocrypt -mode ctf -algo atbash -op enc -text "hello"

# Base64 编码
./gocrypt -mode ctf -algo base64 -op enc -text "hello"

# Base91 编码
./gocrypt -mode ctf -algo base91 -op enc -text "hello"
```

#### 复杂替换与置换

```
# 维吉尼亚密码 (Vigenere) - 指定密钥
./gocrypt -mode ctf -algo vigenere -op enc -text "hello" -key "KEY"

# 仿射密码 (Affine) - y = (ax + b) % 26
./gocrypt -mode ctf -algo affine -op enc -text "hello" -a 5 -b 8

# 栅栏密码 (Fence) - 指定栏数 (Rails)
./gocrypt -mode ctf -algo fence -op enc -text "hello world" -key 3
```

#### 摩斯与信号类

```
# 摩斯密码 (Morse)
./gocrypt -mode ctf -algo morse -op enc -text "SOS"

# 01 摩斯 (0=点, 1=划)
./gocrypt -mode ctf -algo morse_binary -op enc -text "SOS"

# 培根密码 (Bacon)
./gocrypt -mode ctf -algo bacon -op enc -text "hello"
```

#### 符号与图形密码

```
# 猪圈密码 (Pigpen)
./gocrypt -mode ctf -algo pigpen -op enc -text "HELLO"

# 银河字母 (Galaxy) - 指挥官基恩游戏字体
./gocrypt -mode ctf -algo galaxy -op enc -text "HELLO"

# 象形文字 (Hieroglyph)
./gocrypt -mode ctf -algo hieroglyph -op enc -text "HELLO"

# 核心价值观编码
./gocrypt -mode ctf -algo core_values -op enc -text "hello"

# 当铺密码 (Dangpu) - 汉字笔画映射
./gocrypt -mode ctf -algo dangpu -op enc -text "12345"
```

#### 键盘密码

```
# 手机键盘 (Phone Keypad) - 2=ABC, 3=DEF...
./gocrypt -mode ctf -algo phone_keypad -op enc -text "HELLO"

# 键盘坐标 (Keyboard Grid) - QWE格式
./gocrypt -mode ctf -algo keyboard_grid -op enc -text "HELLO"
```

#### 脑洞编程语言 (Esoteric)

```
# Brainfuck
./gocrypt -mode ctf -algo brainfuck -op enc -text "Hi"

# Ook!
./gocrypt -mode ctf -algo ook -op enc -text "Hi"
```

#### 文件操作

```
# ZIP 伪加密 (修改文件头标记)
./gocrypt -mode ctf -algo zip -op enc -text "flag.zip" -out "flag_locked.zip"

# ZIP 伪加密修复
./gocrypt -mode ctf -algo zip -op dec -text "flag_locked.zip" -out "flag_unlocked.zip"
```

## ⚠️ 免责声明

本工具仅用于**安全研究、CTF 竞赛及授权测试**。请勿将本工具用于任何非法的攻击行为。使用者需自行承担因使用本工具而产生的一切法律后果，开发者不承担任何责任。

## 🤝 贡献指南

欢迎提交 Issue 和 Pull Request 来添加新的算法或改进现有功能！

**GoCrypt** - 解密未知的钥匙 🗝️
