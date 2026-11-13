// Deliberately vulnerable sample for CodeSift tests. Never deploy.
package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

var db *sql.DB

func run(w http.ResponseWriter, r *http.Request) {
	// REAL: command injection through a shell
	out, _ := exec.Command("sh", "-c", "ping -c 1 "+r.URL.Query().Get("host")).Output()
	w.Write(out)
}

func user(w http.ResponseWriter, r *http.Request) {
	// REAL: SQL injection via Sprintf
	q := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", r.URL.Query().Get("name"))
	rows, _ := db.Query(q)
	defer rows.Close()
}

func client() *http.Client {
	// REAL: TLS verification disabled
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func etag(body []byte) string {
	// FALSE POSITIVE: md5 as a non-security ETag
	return fmt.Sprintf("%x", md5.Sum(body))
}

func main() {
	http.HandleFunc("/run", run)
	http.HandleFunc("/user", user)
	_ = client()
	_ = etag(nil)
	http.ListenAndServe(":8080", nil)
}
