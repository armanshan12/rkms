package main

import (
	"fmt"
	"net/http"

	logger "github.com/sirupsen/logrus"
)

var rkmsHandler *RKMS

func main() {
	config := LoadConfiguration()

	level, err := logger.ParseLevel(config.Logger.Level)
	if err != nil {
		logger.Fatal(err)
	}
	logger.SetLevel(level)

	rkms, err := NewRKMSWithDynamoDB(config.KMS, config.DynamoDB)
	if err != nil {
		logger.Fatal(err)
		return
	}
	rkmsHandler = rkms

	path := "/api/" + config.Server.APIVersion + "/key"
	http.HandleFunc(path, decorator(getKey))
	err = http.ListenAndServe(":"+config.Server.Port, nil)
	if err != nil {
		logger.Fatal("ListenAndServe: ", err)
	}
}

func decorator(handler func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		//we will always return in JSON
		w.Header().Set("Content-Type", "application/json")

		handler(w, r)
	}
}

func getKey(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		resp := ConstructErrorResponse("BadRequest", "id query parameter is required")
		fmt.Fprintln(w, resp)
		return
	}

	ctx := r.Context()
	plaintextDataKey, err := rkmsHandler.GetPlaintextDataKey(ctx, id)
	if err != nil {
		//TODO: do a better error handling based on the type of error
		w.WriteHeader(http.StatusInternalServerError)
		resp := ConstructErrorResponse("InternalServerError", err.Error())
		fmt.Fprintln(w, resp)
		return
	}

	w.WriteHeader(http.StatusOK)
	resp := ConstructGetKeyResponse(id, *plaintextDataKey)
	fmt.Fprintln(w, resp)
}
