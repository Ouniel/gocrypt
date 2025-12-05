package main

import (
	"bufio"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"hash"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/GehirnInc/crypt/apr1_crypt"
	"github.com/GehirnInc/crypt/md5_crypt"
	"github.com/GehirnInc/crypt/sha256_crypt"
	"github.com/GehirnInc/crypt/sha512_crypt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/md4"
)

// ==================== 全局配置与结构 ====================

// AlgoFunc 定义加密函数的签名
// pass: 密码明文, salt: 盐值 (命令行传入), target: 目标哈希(用于从哈希中提取salt，如MSSQL或Linux Crypt)
type AlgoFunc func(pass, salt, target string) string

type Algorithm struct {
	Name string
	Func AlgoFunc
	// IsSalted 标记该算法是否依赖外部 Salt (命令行 -salt)。
	// false 表示该算法自带 Salt (如 bcrypt, linux_md5) 或不需要 Salt。
	// true 表示该算法需要外部 Salt (如 md5($pass.$salt))。
	IsSalted bool
}

var algorithms []Algorithm

// ==================== 主程序入口 ====================

func main() {
	// 自定义 Usage 信息
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "高级密码加解密工具 gocrypt (Optimized)\n\n")
		fmt.Fprintf(os.Stderr, "用法:\n")
		fmt.Fprintf(os.Stderr, "  %s [选项]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "选项:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\n提示:\n")
		fmt.Fprintf(os.Stderr, "  * 对于 Linux/Bcrypt 哈希，无需提供 -salt，程序会自动从目标哈希中提取。\n")
		fmt.Fprintf(os.Stderr, "  * 对于 md5($pass.$salt) 类哈希，必须提供 -salt 参数。\n")
	}

	// 命令行参数定义
	mode := flag.String("mode", "enc", "运行模式: 'enc' (加密) 或 'crack' (解密/破解)")
	text := flag.String("text", "", "输入文本: 加密模式下为明文，破解模式下为目标密文")
	salt := flag.String("salt", "", "盐值 (仅针对非内嵌 Salt 的算法需要手动指定)")
	dictPath := flag.String("dict", "pass.txt", "密码字典文件路径 (仅 crack 模式有效)")
	threads := flag.Int("t", 8, "破解时的并发线程数 (针对 bcrypt 等慢哈希可适当调整)")

	flag.Parse()

	// 1. 参数校验
	if flag.NFlag() == 0 || *text == "" {
		fmt.Println("[-] 错误: 请输入必要的参数 (至少需要 -text)")
		flag.Usage()
		return
	}

	// 注册算法
	registerAlgorithms()
	registerLinuxAlgorithms()

	if *mode == "enc" {
		doEncrypt(*text, *salt)
	} else if *mode == "crack" {
		// 检查字典
		if _, err := os.Stat(*dictPath); os.IsNotExist(err) {
			fmt.Printf("[-] 错误: 字典文件 '%s' 不存在。\n", *dictPath)
			return
		}
		// 盐值警告策略
		if *salt == "" {
			fmt.Println("[!] 提示: 未提供 -salt 参数。对于 Linux/Bcrypt/MSSQL 等内嵌盐算法无影响，但对于 md5($pass.$salt) 类算法将使用空盐值。")
		}
		doCrack(*text, *salt, *dictPath, *threads)
	} else {
		fmt.Printf("[-] 错误: 未知模式 '%s'\n", *mode)
		flag.Usage()
	}
}

// ==================== 核心逻辑：加密 ====================

func doEncrypt(password, salt string) {
	fmt.Printf("[*] 正在加密文本: '%s' | Salt: '%s'\n", password, salt)
	fmt.Println("----------------------------------------------------------------")
	fmt.Printf("%-35s | %s\n", "Algorithm", "Result")
	fmt.Println("----------------------------------------------------------------")

	for _, algo := range algorithms {
		// Encrypt 模式下，target 传空
		res := algo.Func(password, salt, "")
		fmt.Printf("\033[32m%-35s\033[0m : %s\n", algo.Name, res)
	}
	fmt.Println("----------------------------------------------------------------")
}

// ==================== 核心逻辑：破解 ====================

func doCrack(targetHash, cliSalt, dictPath string, threads int) {
	targetHash = strings.TrimSpace(targetHash)
	fmt.Printf("[*] 开始破解: %s\n", targetHash)

	// 1. 识别可能的算法 (优化：减少无谓计算)
	candidates := identifyHashType(targetHash)
	if len(candidates) > 0 {
		fmt.Printf("[+] 识别到可能的加密类型 (%d种): %v\n", len(candidates), candidates)
	} else {
		fmt.Println("[!] 无法自动识别哈希类型，将尝试所有算法 (速度可能较慢)...")
	}

	passChan := make(chan string, threads*2)
	var wg sync.WaitGroup
	found := false
	var mu sync.Mutex

	startTime := time.Now()

	// 启动 Worker
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range passChan {
				mu.Lock()
				if found {
					mu.Unlock()
					continue
				}
				mu.Unlock()

				// 决定要跑哪些算法
				// 如果有识别结果，只跑识别出的算法；否则全量跑
				algosToRun := algorithms

				for _, algo := range algosToRun {
					// 过滤逻辑
					if len(candidates) > 0 && !contains(candidates, algo.Name) {
						continue
					}

					// 计算哈希
					// 优化：cliSalt 只有在特定算法下才会被使用，内嵌盐算法会自动忽略它并使用 targetHash 解析
					res := algo.Func(p, cliSalt, targetHash)

					if strings.EqualFold(res, targetHash) {
						mu.Lock()
						if !found {
							found = true
							fmt.Println("\n\n==================================================")
							fmt.Printf("\033[31m[SUCCESS] 密码已找到!\033[0m\n")
							fmt.Printf("Algorithm    : %s\n", algo.Name)
							fmt.Printf("Password     : %s\n", p)
							fmt.Printf("Hash         : %s\n", res)
							if cliSalt != "" && algo.IsSalted {
								fmt.Printf("External Salt: %s\n", cliSalt)
							}
							// 优化输出格式，方便后续 Hashcat 使用
							fmt.Printf("Format (GPU) : %s\n", formatForHashcat(p, cliSalt, res, algo))
							fmt.Println("==================================================")
						}
						mu.Unlock()
					}
				}
			}
		}()
	}

	// === 阶段 1：字典破解 ===
	fmt.Printf("[*] 加载字典: %s\n", dictPath)
	file, err := os.Open(dictPath)
	if err == nil {
		scanner := bufio.NewScanner(file)
		count := 0
		for scanner.Scan() {
			mu.Lock()
			if found {
				mu.Unlock()
				break
			}
			mu.Unlock()

			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				passChan <- line
				count++
				if count%2000 == 0 {
					fmt.Printf("\r[*] [Dict] 已尝试: %d ...", count)
				}
			}
		}
		file.Close()
	}

	// 等待队列消化
	time.Sleep(500 * time.Millisecond)

	mu.Lock()
	if found {
		mu.Unlock()
		close(passChan)
		wg.Wait()
		return
	}
	mu.Unlock()

	// === 阶段 2：交互式暴力破解 ===
	fmt.Println("\n[-] 字典已耗尽，未找到密码。")
	fmt.Print("[?] 是否尝试暴力破解 (1-6位数字+小写字母)? [y/N]: ")
	reader := bufio.NewReader(os.Stdin)
	char, _, _ := reader.ReadRune()

	if char == 'y' || char == 'Y' {
		fmt.Println("[*] 开始暴力破解...")
		bruteForceGenerator(passChan, &found, &mu)
	} else {
		fmt.Println("[*] 已停止。")
	}

	close(passChan)
	wg.Wait()

	if !found {
		fmt.Printf("\n[-] 失败。耗时: %s\n", time.Since(startTime))
	}
}

func bruteForceGenerator(out chan<- string, found *bool, mu *sync.Mutex) {
	charset := "0123456789abcdefghijklmnopqrstuvwxyz"
	for length := 1; length <= 6; length++ {
		fmt.Printf("\n[*] [Brute] 长度: %d\n", length)
		generateRecursive("", length, charset, out, found, mu)
		mu.Lock()
		if *found {
			mu.Unlock()
			return
		}
		mu.Unlock()
	}
}

func generateRecursive(current string, length int, charset string, out chan<- string, found *bool, mu *sync.Mutex) {
	mu.Lock()
	if *found {
		mu.Unlock()
		return
	}
	mu.Unlock()

	if length == 0 {
		out <- current
		return
	}
	for _, char := range charset {
		generateRecursive(current+string(char), length-1, charset, out, found, mu)
	}
}

// ==================== 算法注册 ====================

func registerAlgorithms() {
	// 基础编码
	add("base64", false, func(p, s, t string) string {
		return base64.StdEncoding.EncodeToString([]byte(p))
	})

	// MD5 系列
	add("md5", false, func(p, s, t string) string { return md5Hex(p) })

	// MySQL Old / MD5 Middle 冲突处理：两者长度一致，identifyHashType 会同时返回
	add("md5_middle", false, func(p, s, t string) string {
		h := md5Hex(p)
		if len(h) == 32 {
			return h[8:24]
		}
		return ""
	})

	add("md5(md5($pass))", false, func(p, s, t string) string { return md5Hex(md5Hex(p)) })
	add("md5(md5(md5($pass)))", false, func(p, s, t string) string { return md5Hex(md5Hex(md5Hex(p))) })

	// Unicode 支持 (UTF-16LE, Windows 标准)
	add("md5(unicode)", false, func(p, s, t string) string {
		return hashHex(md5.New(), encodeUTF16LE(p))
	})

	// Unicode Big Endian 支持 (新增: 某些非 Windows 系统)
	add("md5(unicode_be)", false, func(p, s, t string) string {
		return hashHex(md5.New(), encodeUTF16BE(p))
	})

	add("md5(base64)", false, func(p, s, t string) string {
		return md5Hex(base64.StdEncoding.EncodeToString([]byte(p)))
	})

	// MySQL
	add("mysql", false, func(p, s, t string) string { return mysqlOldPassword(p) })
	add("mysql5", false, func(p, s, t string) string { return sha1Hex(sha1HexBytes([]byte(p))) })

	// NTLM
	add("ntlm", false, func(p, s, t string) string {
		h := md4.New()
		h.Write(encodeUTF16LE(p))
		return hex.EncodeToString(h.Sum(nil))
	})

	// SHA 系列
	add("sha1", false, func(p, s, t string) string { return sha1Hex(p) })
	add("sha1(sha1($pass))", false, func(p, s, t string) string { return sha1Hex(sha1Hex(p)) })
	add("sha1(md5($pass))", false, func(p, s, t string) string { return sha1Hex(md5Hex(p)) })
	add("md5(sha1($pass))", false, func(p, s, t string) string { return md5Hex(sha1Hex(p)) })
	add("sha256", false, func(p, s, t string) string { return sha256Hex(p) })
	add("sha256(md5($pass))", false, func(p, s, t string) string { return sha256Hex(md5Hex(p)) })
	add("sha384", false, func(p, s, t string) string { return sha384Hex(p) })
	add("sha512", false, func(p, s, t string) string { return sha512Hex(p) })

	// Salted MD5 (需要 IsSalted = true)
	add("md5(md5($pass).$salt);VB;DZ", true, func(p, s, t string) string { return md5Hex(md5Hex(p) + s) })
	add("md5($pass.$salt)", true, func(p, s, t string) string { return md5Hex(p + s) })
	add("md5($salt.$pass)", true, func(p, s, t string) string { return md5Hex(s + p) })
	add("md5($salt.$pass.$salt)", true, func(p, s, t string) string { return md5Hex(s + p + s) })
	add("md5($salt.md5($pass))", true, func(p, s, t string) string { return md5Hex(s + md5Hex(p)) })
	add("md5(md5($salt).$pass)", true, func(p, s, t string) string { return md5Hex(md5Hex(s) + p) })
	add("md5($pass.md5($salt))", true, func(p, s, t string) string { return md5Hex(p + md5Hex(s)) })
	add("md5(md5($salt).md5($pass))", true, func(p, s, t string) string { return md5Hex(md5Hex(s) + md5Hex(p)) })
	add("md5(md5($pass).md5($salt))", true, func(p, s, t string) string { return md5Hex(md5Hex(p) + md5Hex(s)) })

	// Complex
	add("md5(substring(md5($pass),8,16))", false, func(p, s, t string) string {
		m := md5Hex(p)
		if len(m) == 32 {
			return m[8:24]
		}
		return ""
	})

	// Salted SHA (需要 IsSalted = true)
	add("sha1($pass.$salt)", true, func(p, s, t string) string { return sha1Hex(p + s) })
	add("sha1($salt.$pass)", true, func(p, s, t string) string { return sha1Hex(s + p) })
	add("sha256($pass.$salt)", true, func(p, s, t string) string { return sha256Hex(p + s) })
	add("sha256($salt.$pass)", true, func(p, s, t string) string { return sha256Hex(s + p) })
	add("sha512($pass.$salt)", true, func(p, s, t string) string { return sha512Hex(p + s) })
	add("sha512($salt.$pass)", true, func(p, s, t string) string { return sha512Hex(s + p) })

	// MSSQL 2015 / 2012+
	// 优化：增强切片安全性，防止 panic
	add("MSSQL2015", false, func(p, s, t string) string {
		var saltBytes []byte
		var err error

		// 破解模式: 从 target 提取 Salt
		if t != "" && strings.HasPrefix(t, "0x0100") {
			if len(t) < 14 {
				return "error_target_len"
			} // Safety Check
			saltHex := t[6:14] // 固定 8 字节 Hex
			saltBytes, err = hex.DecodeString(saltHex)
			if err != nil {
				return "error_salt_decode"
			}
		} else if s != "" {
			// 加密模式: 使用 CLI Salt
			saltBytes, err = hex.DecodeString(s)
			if err != nil {
				saltBytes = []byte(s)
			}
		} else {
			return "need_salt"
		}

		passRef := encodeUTF16LE(p)
		h := sha1.New()
		h.Write(passRef)
		h.Write(saltBytes)
		return "0x0100" + hex.EncodeToString(saltBytes) + hex.EncodeToString(h.Sum(nil))
	})
}

// 注册 Linux/System 相关算法 (内嵌 Salt)
func registerLinuxAlgorithms() {
	// 通用生成器逻辑：如果 target 存在，用 target 验证；否则生成新 Hash
	gen := func(p, t, prefix string, c interface {
		Generate(key, salt []byte) (string, error)
	}) string {
		if t != "" {
			// 破解模式：从 t 提取 salt 并验证
			// 注意：t 必须包含完整的 $id$salt$hash
			hash, err := c.Generate([]byte(p), []byte(t))
			if err == nil && hash == t {
				return t
			}
			return ""
		}
		// 加密模式：生成随机盐或默认盐
		salt := prefix + "salt" // 简化处理，实际应生成随机盐
		hash, _ := c.Generate([]byte(p), []byte(salt))
		return hash
	}

	add("linux_md5_crypt", false, func(p, s, t string) string {
		return gen(p, t, "$1$", md5_crypt.New())
	})
	add("linux_sha256_crypt", false, func(p, s, t string) string {
		return gen(p, t, "$5$", sha256_crypt.New())
	})
	add("linux_sha512_crypt", false, func(p, s, t string) string {
		return gen(p, t, "$6$", sha512_crypt.New())
	})
	add("apache_apr1_crypt", false, func(p, s, t string) string {
		return gen(p, t, "$apr1$", apr1_crypt.New())
	})

	add("bcrypt", false, func(p, s, t string) string {
		if t != "" {
			err := bcrypt.CompareHashAndPassword([]byte(t), []byte(p))
			if err == nil {
				return t
			}
			return ""
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
		if err != nil {
			return "error"
		}
		return string(hash)
	})
}

func add(name string, isSalted bool, f AlgoFunc) {
	algorithms = append(algorithms, Algorithm{Name: name, IsSalted: isSalted, Func: f})
}

// ==================== 辅助函数 ====================

func identifyHashType(h string) []string {
	h = strings.TrimSpace(h)
	var candidates []string

	// MCF 格式优先 (精确匹配)
	if strings.HasPrefix(h, "$1$") {
		return []string{"linux_md5_crypt"}
	}
	if strings.HasPrefix(h, "$5$") {
		return []string{"linux_sha256_crypt"}
	}
	if strings.HasPrefix(h, "$6$") {
		return []string{"linux_sha512_crypt"}
	}
	if strings.HasPrefix(h, "$apr1$") {
		return []string{"apache_apr1_crypt"}
	}
	if strings.HasPrefix(h, "$2a$") || strings.HasPrefix(h, "$2b$") || strings.HasPrefix(h, "$2y$") {
		return []string{"bcrypt"}
	}

	// Hex 类处理
	hLower := strings.ToLower(h)
	cleanH := strings.TrimPrefix(hLower, "0x")
	l := len(cleanH)

	// MSSQL (带头部的 Hex)
	if strings.HasPrefix(hLower, "0x0100") {
		candidates = append(candidates, "MSSQL2015")
	}

	// 16 Hex (64 bit) -> 冲突区
	if l == 16 {
		candidates = append(candidates, "mysql", "md5_middle")
	}

	// 32 Hex (128 bit) -> MD5 家族
	if l == 32 {
		candidates = append(candidates, "md5", "ntlm", "md5(unicode)", "md5(unicode_be)", "md5(base64)")
		candidates = append(candidates, "md5(md5($pass))", "md5(md5(md5($pass)))")
		candidates = append(candidates, "md5(substring(md5($pass),8,16))")
		// 加盐 MD5 只有在全量跑或无法区分时尝试，但长度也是 32
		candidates = append(candidates, "md5(md5($pass).$salt);VB;DZ", "md5($pass.$salt)", "md5($salt.$pass)")
	}

	// 40 Hex (160 bit) -> SHA1 家族
	if l == 40 {
		candidates = append(candidates, "sha1", "mysql5", "sha1(sha1($pass))", "sha1(md5($pass))", "md5(sha1($pass))")
		candidates = append(candidates, "sha1($pass.$salt)")
	}

	if l == 64 {
		candidates = append(candidates, "sha256", "sha256(md5($pass))", "sha256($pass.$salt)")
	}
	if l == 96 {
		candidates = append(candidates, "sha384")
	}
	if l == 128 {
		candidates = append(candidates, "sha512", "sha512($pass.$salt)")
	}

	return candidates
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// 格式化输出供 Hashcat / GPU 使用
func formatForHashcat(pass, salt, hash string, algo Algorithm) string {
	if algo.IsSalted {
		return fmt.Sprintf("%s:%s", hash, salt) // 常见 pass:salt 或 hash:salt
	}
	return hash // 无盐哈希直接输出 hash
}

// 哈希计算辅助
func md5Hex(s string) string       { return hashHex(md5.New(), []byte(s)) }
func sha1Hex(s string) string      { return hashHex(sha1.New(), []byte(s)) }
func sha1HexBytes(b []byte) string { return hashHex(sha1.New(), b) }
func sha256Hex(s string) string    { return hashHex(sha256.New(), []byte(s)) }
func sha384Hex(s string) string    { return hashHex(sha512.New384(), []byte(s)) }
func sha512Hex(s string) string    { return hashHex(sha512.New(), []byte(s)) }

func hashHex(h hash.Hash, data []byte) string {
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

// UTF-16 Little Endian (Windows/Standard)
func encodeUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b
}

// UTF-16 Big Endian (Java/Mainframe/AIX)
func encodeUTF16BE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	b := make([]byte, len(u16)*2)
	for i, v := range u16 {
		binary.BigEndian.PutUint16(b[i*2:], v)
	}
	return b
}

// MySQL 3.23 legacy hash
func mysqlOldPassword(arg string) string {
	var nr, nr2 uint32 = 1345345333, 0x12345671
	var add, tmp uint32 = 7, 0
	for _, r := range arg {
		if r == ' ' || r == '\t' {
			continue
		}
		tmp = uint32(byte(r))
		nr ^= (((nr & 63) + add) * tmp) + (nr << 8)
		nr2 += (nr2 << 8) ^ nr
		add += tmp
	}
	return fmt.Sprintf("%08x%08x", nr&0x7FFFFFFF, nr2&0x7FFFFFFF)
}
