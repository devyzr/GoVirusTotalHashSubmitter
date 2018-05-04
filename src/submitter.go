// A script that'll search inside a folder, hash all the files and send the hashes to virus total.
// Currently I don't process the full JSON response, but I'll get that done later.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	start_time := time.Now()
	file_dir := "./files_to_hash/"
	file_dir_contents, err := ioutil.ReadDir(file_dir)
	if err != nil {
		log.Fatal("Error checking directory. ", err)
	}

	var files_to_hash []string

	for _, f := range file_dir_contents {
		if !f.IsDir() {
			filepath := file_dir + f.Name()
			files_to_hash = append(files_to_hash, filepath)
		}
	}

	// Virus total API requests are limited to 4/minute
	// but sometimes requests are cached and don't count
	// and other times they're just plain nice.
	// Either way, response code 204 is handled later on.
	seconds := 5
	sleepTime := time.Duration(seconds) * time.Second

	for n, f := range files_to_hash {
		if n > 0 && n != len(files_to_hash) {
			fmt.Printf("Waiting %v to respect rate limiting...\n", sleepTime)
			time.Sleep(sleepTime)
		}

		hash := hash_256(f)
		vtr := submit_hash(hash)
		filename := strings.Replace(f, file_dir, "", 1)
		fmt.Printf("\nHash for '%v':\n%v\n", filename, hash)
		fmt.Println("Virus Total Response:")
		var res_code_meaning string
		switch vtr.Response_code {
		case 0:
			res_code_meaning = "No Results found"
		case 1:
			res_code_meaning = "Results found"
		case -1:
			res_code_meaning = "Error"
		}

		if vtr.Response_code == 1 {
			fmt.Printf("Response code:\t%v\nTotal scans:\t%v\nPositives:\t%v\n",
				res_code_meaning, vtr.Total, vtr.Positives)
		} else {
			fmt.Printf("Response code: %v.\n", res_code_meaning)
		}
	}
	end_time := time.Now()

	fmt.Printf("\nStarted at %v, finished at %v, processed %v files.\n", start_time, end_time, len(files_to_hash))
}

func hash_256(filename string) string {
	file_to_hash, err := os.Open(filename)
	if err != nil {
		log.Fatal("Error opening file. ", err)
	}
	defer file_to_hash.Close()

	hasher := sha256.New()

	_, err = io.Copy(hasher, file_to_hash)
	if err != nil {
		log.Fatal("Error copying file to hasher. ", err)
	}

	sha := hex.EncodeToString(hasher.Sum(nil))
	return sha
}

func submit_hash(hash string) VirusTotalResponse {
	api_key := ""
	url := "https://www.virustotal.com/vtapi/v2/file/report?apikey=" + api_key + "&resource=" + hash

	vtr := VirusTotalResponse{Response_code: -1, Total: 0, Positives: 0}

	response, err := http.Get(url)
	if err != nil {
		log.Fatal("Error submitting hash. ", err)
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case 400:
		log.Fatal("Bad request.")

	case 403:
		log.Fatal("Request forbidden.")

	case 204:
		fmt.Println("Request limit exceeded, waiting 15s and trying again...")
		time.Sleep(time.Duration(15) * time.Second)
		vtr = submit_hash(hash)
		return vtr

	case 200:
		err = json.NewDecoder(response.Body).Decode(&vtr)
		if err != nil {
			log.Fatal("Error reading response body. ", err)
		}
		return vtr

	default:
		log.Fatal("invalid HTTP response: ", response.Status)
	}

	return vtr
}

// We only care about total scans and positives for now.
type VirusTotalResponse struct {
	Response_code int
	Total         int
	Positives     int
}
