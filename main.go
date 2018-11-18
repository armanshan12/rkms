package main

import (
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
	http.HandleFunc(path, getKey)
	err = http.ListenAndServe(":"+config.Server.Port, nil)
	if err != nil {
		logger.Fatal("ListenAndServe: ", err)
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

	ctx := r.Context()
	plaintextDataKey, err := rkmsHandler.GetPlaintextDataKey(ctx, id)
	if err != nil {
		//TODO: do a better error handling based on the type of error
		b := ConstructErrorResponse("InternalError", err.Error())
		w.Write(b)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	b := ConstructGetKeyResponse(&id, plaintextDataKey)
	w.Write(b)
	w.WriteHeader(http.StatusOK)
}
