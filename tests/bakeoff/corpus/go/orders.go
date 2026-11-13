package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
)

var db *sql.DB

func order(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "bad id", 400)
		return
	}
	rows, err := db.Query(fmt.Sprintf("SELECT total FROM orders WHERE id = %d", id))
	if err != nil {
		http.Error(w, "error", 500)
		return
	}
	defer rows.Close()
}

func main() {
	http.HandleFunc("/order", order)
	http.ListenAndServe(":8080", nil)
}
