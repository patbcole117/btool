package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "errors"
    "fmt"
    "flag"
    "os"
    "strconv"
)

var (
    COLUMNS      = 16
    flag_help   = flag.Bool("h", false, "Display usage.")
    flag_quiet  = flag.Bool("q", false, "Only print final bytes on one line.")
    flag_bytes   = flag.String("b", "", "A string of bytes: \"\\x41\\x42...\"")
    flag_inFile  = flag.String("i", "", "Read bytes from file.")
    flag_outFile = flag.String("o", "", "Output to file.")
    flag_enc     = flag.String("e", "", "Encrypt: xor, aes.")
    flag_dec     = flag.String("d", "", "Decrypt: xor, aes.")
    
    flag_cyclic  = flag.Int("c", 0, "Generate deBruijn pattern of length n")
    flag_cyclen  = flag.String("p", "", "Find the offset of a substrinng in deBruijn.")

    ErrInvalidEnc   = errors.New("invalid encryption")
    ErrInvalidDec   = errors.New("invalid decryption")
    ErrInvalidArgsGroup  = errors.New("cannot use -b & -i or -e & -d togeather")
)

func main() {

    args := os.Args
    flag.Parse()
    if *flag_help || len(args) < 2 {
        flag.Usage()
        os.Exit(0)
    }

    err := checkArgs(args)
    checkErr(err)
    bytes := make([]byte, 0)
    if *flag_bytes != "" {
        *flag_bytes, err = strconv.Unquote(`"` + *flag_bytes + `"`)
        checkErr(err)
        bytes = []byte(*flag_bytes)
        qPrint(fmt.Sprintf("[+] Read %d bytes from stdin.\n", len(bytes)))

    } else if *flag_inFile != "" {
        bytes, err = os.ReadFile(*flag_inFile)
        checkErr(err)
        qPrint(fmt.Sprintf("[+] Read %d bytes from %s.\n", len(bytes),
        *flag_inFile))
    }

    if !(*flag_quiet) {
        fmt.Println(printBytes(bytes))
    }

    switch *flag_enc {
    case "":
        break
    case "aes":
        bytes, err = e_aes(&bytes)
        checkErr(err)
    case "xor":
        e_xor(&bytes)
    default:
        panic(ErrInvalidEnc)
    }

    switch *flag_dec {
    case "":
        break
    case "aes":
        bytes, err = d_aes(&bytes)
        checkErr(err)
    case "xor":
        d_xor(&bytes)
    default:
        panic(ErrInvalidDec)
    }

    if (*flag_dec != "" || *flag_enc != "") && !(*flag_quiet) {
        fmt.Println(printBytes(bytes))
    }

    if *flag_outFile != "" {
        err := os.WriteFile(*flag_outFile, bytes, 0600)
        checkErr(err)
        qPrint(fmt.Sprintf("[+] Wrote %d bytes to %s.\n", len(bytes),
        *flag_outFile))
    }
}

func printBytes(bytes []byte) string {
    s := ""
    for i := 0; i < len(bytes); i++ {
        if i%(COLUMNS) == 0 {
            s = s + "\n"
        } else if i%(COLUMNS/2) == 0 {
            s = s + " "
        }
        s = s + fmt.Sprintf("\\x%02x", bytes[i])
    }
    s = s + "\n"
    return s
}

func checkErr(err error) {
    if err != nil {
        panic(err)
    }
}

func checkArgs(args []string) error{

    if (*flag_inFile != "" && *flag_bytes != "") ||
       (*flag_enc != "" && *flag_dec != "") {
        return ErrInvalidArgsGroup
    }
    return nil
}

// crypto
func e_keygen(s int) ([]byte, error) {
    k := make([]byte, s)
    _, err := rand.Read(k)
    if err != nil {
        return nil, err
    }
    return k, nil
}

func e_xor(pbytes *[]byte) {
    var key string
    fmt.Print("Key:") 
    fmt.Scanln(&key)

    for i := 0; i < len(*pbytes); i++ {
        (*pbytes)[i] = (*pbytes)[i] ^ key[i%len(key)]
    }
    qPrint(fmt.Sprintf("[+] Encrypted %d bytes with key \"%s\"\n",
    len(*pbytes), key))
    key = ""
}

func d_xor(pbytes *[]byte) {
    var key string
    fmt.Print("Key:") 
    fmt.Scanln(&key)

    for i := 0; i < len(*pbytes); i++ {
        (*pbytes)[i] = (*pbytes)[i] ^ key[i%len(key)]
    }
    qPrint(fmt.Sprintf("[+] Decrypted %d bytes with key \"%s\"\n",
    len(*pbytes), key))
    key = ""
}

func e_aes(pbytes *[]byte) ([]byte, error) {
    key, err := e_keygen(32)
    if err != nil {
        return nil, err
    }

    err = os.WriteFile("a.key", key, 0600)
    if err != nil {
        return nil, err
    }

    aes, err := aes.NewCipher(key)
    if err != nil {
         return nil, err
    }

    gcm, err := cipher.NewGCM(aes)
    if err != nil {
         return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    _, err = rand.Read(nonce)
    if err != nil {
         return nil, err
    }

    bytes_ct := gcm.Seal(nonce, nonce, *pbytes, nil)

    qPrint(fmt.Sprintf("[+] Encrypted %d bytes with AES-256. Key is saved to "+
    "\"a.key\". \n[+] Result is %d bytes.\n", len(*pbytes), len(bytes_ct)))

    return bytes_ct, nil
}

func d_aes(pbytes_ctnonce *[]byte) ([]byte, error) {
    key, err := os.ReadFile("a.key")
    if err != nil {
        return nil, err
    }

    aes, err := aes.NewCipher(key)
    if  err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(aes)
    if err != nil {
        return nil, err
    }

    nSize := gcm.NonceSize()
    nonce, bytes_ct :=  (*pbytes_ctnonce)[:nSize], (*pbytes_ctnonce)[nSize:]

    bytes_pt, err :=  gcm.Open(nil, nonce, bytes_ct, nil)
    if err != nil {
        return nil, err
    }
    qPrint(fmt.Sprintf("[+] Decrypted %d bytes with AES-256. Key used was "+
    "\"a.key\". \n[+] Result is %d bytes.\n", len(*pbytes_ctnonce), len(bytes_pt)))
    return bytes_pt, nil
}

func qPrint(msg string) {
 if !(*flag_quiet) {
    fmt.Print(msg)
 }
}

