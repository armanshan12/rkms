package main

import (
	"net/http"

	logger "github.com/sirupsen/logrus"
)

var config = LoadConfiguration()
var rkmsHandler *RKMS

func main() {
	//TODO: make this configurable
	logger.SetLevel(logger.DebugLevel)

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

	key, err := rkmsHandler.GetPlaintextDataKey(id)
	if err != nil {
		//TODO: do a better error handling based on the type of error
		b := ConstructErrorResponse("InternalError", err.Error())
		w.Write(b)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	b := ConstructGetKeyResponse(key)
	w.Write(b)
	w.WriteHeader(http.StatusOK)
}
