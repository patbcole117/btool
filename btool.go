package main

import (
    "fmt"
    "flag"
    "os"
    "errors"
    "strconv"
)


var pbool_help   = flag.Bool("h", false, "Display usage.")
var pstr_bytes   = flag.String("b", "", "A string of bytes: \"\\x41\\x42...\"")
var pstr_inFile  = flag.String("i", "", "Read bytes from file.")
var pstr_outFile = flag.String("o", "", "Output to file.")
var pint_col     = flag.Int("c", 16, "Output columns.")
var pstr_enc     = flag.String("e", "", "Encrypt: xor.")
var pstr_dec     = flag.String("d", "", "Decrypt: xor.")

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
        fmt.Printf("[+] Read %d bytes from stdin.\n", len(ar_b))

    } else if *pstr_inFile != "" {
        ar_b, err = os.ReadFile(*pstr_inFile)
        checkErr(err)
        fmt.Printf("[+] Read %d bytes from %s.\n", len(ar_b), *pstr_inFile)
    }

    printBytes(ar_b)

    switch *pstr_enc {
    case "":
        break
    case "xor":
        e_xor(&ar_b)
    }

    switch *pstr_dec {
    case "":
        break
    case "xor":
        d_xor(&ar_b)
    }

    printBytes(ar_b)

    if *pstr_outFile != "" {
        err := os.WriteFile(*pstr_outFile, ar_b, 0600)
        checkErr(err)
        fmt.Printf("[+] Wrote %d bytes to %s.\n", len(ar_b), *pstr_outFile)
    }
}

func printBytes(ar_b []byte) {
    for i := 0; i < len(ar_b); i++ {
        if i%(*pint_col) == 0 {
            fmt.Println()
        }
        fmt.Printf("\\x%02x", ar_b[i])
    }
    fmt.Printf("\n\n")
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
func e_xor(par_b *[]byte) {
    var key string
    fmt.Print("Key:") 
    fmt.Scanln(&key)

    for i := 0; i < len(*par_b); i++ {
        (*par_b)[i] = (*par_b)[i] ^ key[i%len(key)]
    }
    fmt.Printf("[+] Encrypted %d bytes with key \"%s\"\n", len(*par_b), key)
}

func d_xor(par_b *[]byte) {
    var key string
    fmt.Print("Key:") 
    fmt.Scanln(&key)

    for i := 0; i < len(*par_b); i++ {
        (*par_b)[i] = (*par_b)[i] ^ key[i%len(key)]
    }
    fmt.Printf("[+] Decrypted %d bytes with key \"%s\"\n", len(*par_b), key)
}

