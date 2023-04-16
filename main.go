package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"port-scanner/port"

	"github.com/gorilla/mux"
)

type ErrorResponse struct {
	Code    int
	Message string
}
type PortScanRequest struct {
	HostName string `json:"hostname"`
}

func returnLastPortScan(response http.ResponseWriter, request *http.Request) {
	var httpError = ErrorResponse{
		Code: http.StatusInternalServerError, Message: "It's not you it's me.",
	}
	fmt.Println("Endpoint Hit: return port scan")
	result := port.GetOpenPorts("www.freecodecamp.com", port.PortRange{Start: 75, End: 85})

	//json.NewEncoder(w).Encode(DisplayScanResult(result))
	jsonResponse, _ := json.Marshal(result)
	if jsonResponse == nil {
		returnErrorResponse(response, request, httpError)
	} else {
		response.Header().Set("Content-Type", "application/json")
		response.Write(jsonResponse)
	}
	response.Write(jsonResponse)
}

func startPortScan(response http.ResponseWriter, request *http.Request) {
	var httpError = ErrorResponse{
		Code: http.StatusInternalServerError, Message: "It's not you it's me.",
	}
	reqBody, _ := ioutil.ReadAll(request.Body)
	var data = make([]PortScanRequest)
	json.Unmarshal(reqBody, &data)
	fmt.Println(data)
	result := []port.ScanResult{}
	for _, v := range data {
		result = append(result, port.GetOpenPorts(v.HostName, port.PortRange{Start: 75, End: 85}))
	}
	jsonResponse, _ := json.Marshal(result)
	if jsonResponse == nil {
		returnErrorResponse(response, request, httpError)
	} else {
		response.Header().Set("Content-Type", "application/json")
		response.Write(jsonResponse)
	}
	response.Write(jsonResponse)
}

func returnErrorResponse(response http.ResponseWriter, request *http.Request, errorMesage ErrorResponse) {
	httpResponse := &ErrorResponse{Code: errorMesage.Code, Message: errorMesage.Message}
	jsonResponse, err := json.Marshal(httpResponse)
	if err != nil {
		panic(err)
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(errorMesage.Code)
	response.Write(jsonResponse)
}

func setStaticFolder(route *mux.Router) {
	fs := http.FileServer(http.Dir("./public/"))
	route.PathPrefix("/public/").Handler(http.StripPrefix("/public/", fs))
}

func addApproutes(route *mux.Router) {

	setStaticFolder(route)

	route.HandleFunc("/", returnLastPortScan)

	route.HandleFunc("/scan", returnLastPortScan).Methods("GET")
	route.HandleFunc("/scan", startPortScan).Methods("POST")

	fmt.Println("Routes are Loded.")
}

func main() {
	fmt.Println("Server will start at http://localhost:8000/")
	//start := time.Now()

	//port.GetOpenPorts("127.0.0.1", port.PortRange{Start: 2999, End: 3999})

	//port.GetOpenPorts("www.freecodecamp.com", port.PortRange{Start: 75, End: 85})

	// called with ip address
	//port.GetOpenPorts("104.26.10.78", port.PortRange{Start: 8079, End: 8090})

	// verbose called with ip address and no host name returned -- single open port
	//port.GetOpenPorts("104.26.10.78", port.PortRange{Start: 440, End: 450})

	// verbose called with ip adress and valid host name returned -- single open port
	//port.GetOpenPorts("137.74.187.104", port.PortRange{Start: 440, End: 450})

	// verbose called with host name -- multiple ports returned
	//port.GetOpenPorts("scanme.nmap.org", port.PortRange{Start: 20, End: 80})
	//elapsed := time.Since(start)
	//fmt.Printf("Scan duration: %s", elapsed)
	route := mux.NewRouter()
	addApproutes(route)

	log.Fatal(http.ListenAndServe(":8000", route))
}
