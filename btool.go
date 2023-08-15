package main

import (
    "fmt"
    "flag"
    "os"
    "errors"
    "strconv"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
)


var pbool_help   = flag.Bool("h", false, "Display usage.")
var pbool_quiet  = flag.Bool("q", false, "Only print final bytes on one line.")
var pstr_bytes   = flag.String("b", "", "A string of bytes: \"\\x41\\x42...\"")
var pstr_inFile  = flag.String("i", "", "Read bytes from file.")
var pstr_outFile = flag.String("o", "", "Output to file.")
var pint_col     = flag.Int("c", 16, "Output columns.")
var pstr_enc     = flag.String("e", "", "Encrypt: xor, aes.")
var pstr_dec     = flag.String("d", "", "Decrypt: xor, aes.")

func main() {

    args := os.Args
    flag.Parse()
    if *pbool_help || len(args) < 2 {
        flag.Usage()
        os.Exit(0)
    }

    err := checkArgs(args)
    checkErr(err)

    ar_b := make([]byte, 0)
    if *pstr_bytes != "" {
        *pstr_bytes, err = strconv.Unquote(`"` + *pstr_bytes + `"`)
        checkErr(err)
        ar_b = []byte(*pstr_bytes)
        qPrint(fmt.Sprintf("[+] Read %d bytes from stdin.\n", len(ar_b)))

    } else if *pstr_inFile != "" {
        ar_b, err = os.ReadFile(*pstr_inFile)
        checkErr(err)
        qPrint(fmt.Sprintf("[+] Read %d bytes from %s.\n", len(ar_b),
        *pstr_inFile))
    }

    fmt.Println(printBytes(ar_b))

    switch *pstr_enc {
    case "":
        break
    case "aes":
        ar_b, err = e_aes(&ar_b)
        checkErr(err)
        break
    case "xor":
        e_xor(&ar_b)
        break
    default:
        panic("Invalid encryption type.")
    }

    switch *pstr_dec {
    case "":
        break
    case "aes":
        ar_b, err = d_aes(&ar_b)
        checkErr(err)
        break
    case "xor":
        d_xor(&ar_b)
        break
    default:
        panic("Invalid decryption type.")
    }

    if *pstr_dec != "" || *pstr_enc != "" {
        fmt.Print(printBytes(ar_b))
    }

    if *pstr_outFile != "" {
        err := os.WriteFile(*pstr_outFile, ar_b, 0600)
        checkErr(err)
        qPrint(fmt.Sprintf("[+] Wrote %d bytes to %s.\n", len(ar_b),
        *pstr_outFile))
    }
}

func printBytes(ar_b []byte) string {
    s := ""
    for i := 0; i < len(ar_b); i++ {
        if i%(*pint_col) == 0 && !(*pbool_quiet) {
            s = s + "\n"
        }
        s = s + fmt.Sprintf("\\x%02x", ar_b[i])
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

    if (*pstr_inFile != "" && *pstr_bytes != "") ||
       (*pstr_enc != "" && *pstr_dec != "") {
        return errors.New("[-] checkArgs: Invalid flag grouping. "+
                          "Cannot use -b & -i or -e & -d togeather.")
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

func e_xor(par_b *[]byte) {
    var key string
    fmt.Print("Key:") 
    fmt.Scanln(&key)

    for i := 0; i < len(*par_b); i++ {
        (*par_b)[i] = (*par_b)[i] ^ key[i%len(key)]
    }
    qPrint(fmt.Sprintf("[+] Encrypted %d bytes with key \"%s\"\n",
    len(*par_b), key))
    key = ""
}

func d_xor(par_b *[]byte) {
    var key string
    fmt.Print("Key:") 
    fmt.Scanln(&key)

    for i := 0; i < len(*par_b); i++ {
        (*par_b)[i] = (*par_b)[i] ^ key[i%len(key)]
    }
    qPrint(fmt.Sprintf("[+] Decrypted %d bytes with key \"%s\"\n",
    len(*par_b), key))
    key = ""
}

func e_aes(par_b *[]byte) ([]byte, error) {
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

    ar_b_ct := gcm.Seal(nonce, nonce, *par_b, nil)

    qPrint(fmt.Sprintf("[+] Encrypted %d bytes with AES-256. Key is saved to "+
    "\"a.key\". \n[+] Result is %d bytes.", len(*par_b), len(ar_b_ct)))

    return ar_b_ct, nil
}

func d_aes(par_b_ctnonce *[]byte) ([]byte, error) {
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
    nonce, ar_b_ct :=  (*par_b_ctnonce)[:nSize], (*par_b_ctnonce)[nSize:]

    ar_b_pt, err :=  gcm.Open(nil, nonce, ar_b_ct, nil)
    if err != nil {
        return nil, err
    }
    qPrint(fmt.Sprintf("[+] Decrypted %d bytes with AES-256. Key used was "+
    "\"a.key\". \n[+] Result is %d bytes.", len(*par_b_ctnonce), len(ar_b_pt)))
    return ar_b_pt, nil
}

func qPrint(msg string) {
 if !(*pbool_quiet) {
    fmt.Print(msg)
 }
}

