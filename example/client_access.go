// +build clienttest

package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"strings"

	gssapi "github.com/lixiangyun/go-gssapi"
	"github.com/lixiangyun/go-gssapi/spnego"
)

func initClientContext(method, path string,
	bodyf func(ctx *gssapi.CtxId) string) (
	ctx *gssapi.CtxId, r *http.Request) {
	// establish a context
	ctx, _, token, _, _, err := c.InitSecContext(
		c.GSS_C_NO_CREDENTIAL,
		nil,
		prepareServiceName(),
		c.GSS_C_NO_OID,
		0,
		0,
		c.GSS_C_NO_CHANNEL_BINDINGS,
		c.GSS_C_NO_BUFFER)
	defer token.Release()
	if err != nil {
		e, ok := err.(*gssapi.Error)
		if ok && e.Major.ContinueNeeded() {
			log.Fatal("Unexpected GSS_S_CONTINUE_NEEDED")
		}
		log.Fatal(err)
	}

	u := c.ServiceAddress + path
	if !strings.HasPrefix(u, "http://") {
		u = "http://" + u
	}

	body := io.Reader(nil)
	if bodyf != nil {
		body = bytes.NewBufferString(bodyf(ctx))
	}

	r, err = http.NewRequest(method, u, body)
	if err != nil {
		log.Fatal(err)
	}
	spnego.AddSPNEGONegotiate(r.Header, "Authorization", token)

	return ctx, r
}

func TestClientAccess(t *testing.T) {
	// establish a context
	ctx, r := initClientContext(t, "GET", "/access/", nil)
	defer ctx.Release()

	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	out, err := httputil.DumpResponse(resp, true)
	if err != nil {
		t.Fatal(err)
	}

	bodybytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(bodybytes) != "OK" {
		t.Fatalf(
			"Test failed: unexpected response: url:%s, code:%v, response:\n%s",
			r.URL.String(), resp.StatusCode, string(out))
	}
}
