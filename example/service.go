

package main

import (
	"fmt"
	"log"
	"net/http"
)

type DemoServce struct {
}

func (DemoServce)ServeHTTP(rw http.ResponseWriter, r *http.Request) {

	spname, code, err := Spnego.NegotiateVerification(r.Header,rw.Header())
	if code != http.StatusOK {
		log.Printf(err.Error())
		rw.WriteHeader(code)
	}

	body := fmt.Sprintf("%d %s %s %s", code, r.Method, r.URL.String(), spname)

	rw.Write([]byte(body))

	log.Println(body)
}
func Service() error {

	log.Printf("Starting service %s, [%v]\n", ServiceName, ServiceAddress)

	http.Handle("/", DemoServce{})

	err := http.ListenAndServe(ServiceAddress, nil)
	if err != nil {
		return err
	}

	// this isn't executed since the entire container is killed, but for
	// illustration purposes
	Spnego.Release()

	return nil
}
