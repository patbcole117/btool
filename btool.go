package main

import (
    "fmt"
    "flag"
    "os"
    "errors"
)

var MAX_SIZE int = 1024

var pbool_help   = flag.Bool("h", false, "Display usage information.")
var pstr_bytes   = flag.String("b", "", "A string of bytes: \x41, 0x41, 65")
var pstr_inFile  = flag.String("i", "", "Read from the provided file.")
var pstr_outFile = flag.String("o", "", "Write to the provided file.")
var pstr_enc     = flag.String("e", "", "Encrypt: xor")
var pstr_dec     = flag.String("d", "", "Decrypt: xor.")

func main() {

    args := os.Args
    flag.Parse()
    if *pbool_help || len(args) < 2 {
        usage()
        os.Exit(0)
    }

    err := checkArgs(args)
    checkError(err)
    
    var ar_b = make([]byte, MAX_SIZE)
    if *pstr_bytes != "" {
        ar_b := str2Bytes(*pstr_bytes)
    } else if *pstr_inFile != "" {
        ar_b := fromFile(*pstr_inFile)
    }


    if *pstr_enc != "" {
       //TODO ENCRYPT
    } else if *pstr_dec != "" {
       //TODO DECRYPT
    }
}

func checkArgs(args []string) error{

    if (*pstr_inFile != "" && *pstr_bytes != "") ||
       (*pstr_enc != "" && *pstr_dec != "") {
        return errors.New("checkArgs: Invalid flag grouping. "+
                          "Cannot use -b & -i or -e & -d togeather.")
    }
    return nil
}

func checkError(err error) {
    if err != nil {
        panic(err)
    }
}

func usage() {
    fmt.Println("This is help.")
}

func str2Bytes(str_s string) []byte {
    ar_b := []byte(str_s)
    return ar_b
}

func byte2Str(ar_b []byte) string {
    str_b := string(ar_b)
    return str_b
}

func toStdin() {

}

func toFile(ar_b []byte) error {
    
}

func fromStdin() {

}

func fromFile(fName string) byte, error {

    f, err := os.Open(fName)
    defer f.Close()
    checkError(err)
    
    b:= make([]byte, MAX_SIZE)
    n, err := f.Read(b)
    checkError(err)

    fmt.Printf("[+] Read %d bytes from %s.\n", n, fName)

    return b, err
}

// crypto
func e_xor() {

}

func d_xor() {

}

