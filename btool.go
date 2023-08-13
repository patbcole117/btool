package main

import (
    "fmt"
    "flag"
    "os"
)

var pbool_help    = flag.Bool("h", false, "Display usage information.")
var pstr_inFile  = flag.String("i", "", "Read from the provided file.")
var pstr_outFile = flag.String("o", "", "Write to the provided file.")
var pstr_enc     = flag.String("e", "", "Encrypt: xor")
var pstr_dec     = flag.String("d", "", "Decrypt: xor.")

func main() {

    flag.Parse()

    if *pbool_help || len(os.Args) < 2 {
        usage()
    }
}

func usage() {
    fmt.Println("This is help.")
}

func str2Byte() {

}

func byte2Str() {

}

func toStdin() {

}

func toFile() {

}

func fromStdin() {

}

func fromFile() {

}

// crypto
func e_xor() {

}

func d_xor() {

}

