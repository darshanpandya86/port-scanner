package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"

	"github.com/Ullaakut/nmap/v3"
	"github.com/gorilla/mux"
)

type ErrorResponse struct {
	Code    int
	Message string
}
type PortScanRequest struct {
	HostName []string `json:"hostname"`
}
type Result struct {
	HostName  string  `json:"hostname"`
	ListPorts []Ports `json:"Ports"`
}
type Ports struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`

	Service string `xml:"service" json:"service"`
	State   string `xml:"state" json:"state"`
}

func startPortScan(response http.ResponseWriter, request *http.Request) {
	var httpError = ErrorResponse{
		Code: http.StatusInternalServerError, Message: "It's not you it's me.",
	}
	reqBody, _ := ioutil.ReadAll(request.Body)
	var data = PortScanRequest{}
	json.Unmarshal(reqBody, &data)
	//fmt.Println(data)

	r := nmapProcessor(data.HostName)

	jsonResponse, _ := json.Marshal(r)
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

	route.HandleFunc("/scan", startPortScan).Methods("GET")
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

func nmapProcessor(input []string) []Result {
	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
	// with a 5-minute timeout.
	s, err := nmap.NewScanner(
		context.Background(),
		nmap.WithTargets(input...),
		nmap.WithPorts("80,443,843"),
	)
	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	// Executes asynchronously, allowing results to be streamed in real time.
	done := make(chan error)
	result, warnings, err := s.Async(done).Run()
	if err != nil {
		log.Fatal(err)
	}

	// Blocks main until the scan has completed.
	if err := <-done; err != nil {
		if len(*warnings) > 0 {
			log.Printf("run finished with warnings: %s\n", *warnings) // Warnings are non-critical errors from nmap.
		}
		log.Fatal(err)
	}
	var res []Result

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}
		var r Result
		fmt.Printf("Host %q:\n", host.Addresses[0])

		r.HostName = host.Addresses[0].Addr

		for _, port := range host.Ports {
			var p Ports
			p.ID = strconv.FormatUint(uint64(port.ID), 10)
			p.Protocol = port.Protocol
			p.State = port.State.String()
			p.Service = port.Service.Name
			r.ListPorts = append(r.ListPorts, p)

			//fmt.Printf("\tPort %d/%s %s %s\n", p.ID, r.Protocol, r.State, r.Service)
		}
		res = append(res, r)
	}

	return res
}
