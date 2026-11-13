package main

import (
	"database/sql"
	"fmt"
	"net/http"
)

var db *sql.DB

func user(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	query := fmt.Sprintf("SELECT id FROM users WHERE name = '%s'", name)
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, "error", 500)
		return
	}
	defer rows.Close()
}

func main() {
	http.HandleFunc("/user", user)
	http.ListenAndServe(":8080", nil)
}
