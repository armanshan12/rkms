package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type errorResponse struct {
	ErrorType    string `json:"error_type"`
	ErrorMessage string `json:"error_message"`
}

const apiVersion = "v1" //TODO: put in config file

func main() {
	path := "/api/" + apiVersion + "/key"
	http.HandleFunc(path, getKey)
	err := http.ListenAndServe(":8080", nil) //TODO: put port in config file
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

func getKey(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)

		resp := errorResponse{"BadRequest", "id query parameter is required"}
		b, err := json.Marshal(resp)
		if err != nil {
			log.Fatal("Failed to marshal errorResponse object to JSON")
			return
		}

		w.Write(b)
	}
}
