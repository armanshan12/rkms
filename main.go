package main

import (
	"log"
	"net/http"
)

const apiVersion = "v1" //TODO: put in config file

var rkmsHandler = RKMS{}

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
		b := ConstructErrorResponse("BadRequest", "id query parameter is required")
		w.Write(b)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	key, err := rkmsHandler.GetKey(id)
	if err != nil {
		//TODO: do a better error handling based on the type of error
		b := ConstructErrorResponse("InternalError", "Internal server error occurred")
		w.Write(b)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	b := ConstructGetKeyResponse(key)
	w.Write(b)
	w.WriteHeader(http.StatusOK)
}
