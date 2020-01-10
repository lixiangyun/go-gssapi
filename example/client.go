package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"github.com/lixiangyun/go-gssapi/spnego"
)

func Client(spn string, address string, method string, path string, sendBody []byte ) error {

	spname, err := spnego.PrepareServiceName(spn)
	if err != nil {
		return err
	}
	defer spname.Release()

	url := fmt.Sprintf("http://%s/%s", address, path)

	req, err := http.NewRequest(method, url, bytes.NewBuffer(sendBody))
	if err != nil {
		return err
	}

	log.Printf("read to negotiate addition. spname %v", spname)

	err = Spnego.NegotiateAddition(req.Header, spname)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("Expected status 200, got %v", resp.StatusCode))
	}

	recvBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	log.Printf("Rsp: %s\n",string(recvBody))

	return nil
}