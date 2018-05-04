// Simple PoC for a hash submitter to virus total. Here we only worry about the request part.

package main

import (
    "io"
    "log"
    "net/http"
    "os"
)

func main() {
    hash := "7f2cbb647cf198889660edd729b1d425c88c944e989d2b2d90aa226ccda857d5"
    api_key := ""
    url := "https://www.virustotal.com/vtapi/v2/file/report?apikey=" + api_key + "&resource=" + hash

    response, err := http.Get(url)
    if err != nil {
        log.Fatal("Error submitting hash. ", err)
    }
    
    n, err := io.Copy(os.Stdout, response.Body)
    if err != nil {
        log.Fatal(err)
    }

    log.Println("Number of bytes copied to STDOUT:", n)
}