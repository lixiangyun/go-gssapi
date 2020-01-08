

package main

import (
	"encoding/base64"
	"fmt"
	"github.com/lixiangyun/go-gssapi/spnego"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	gssapi "github.com/lixiangyun/go-gssapi"
)

const (
	micHeader = "X-GO-GASSSAPI-MIC"
)

type loggingHandler struct {
	handler func(http.ResponseWriter, *http.Request) (code int, message string)
}

func (h loggingHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	code, message := h.handler(rw, r)
	if code != http.StatusOK {
		rw.WriteHeader(code)
	}
	log.Printf("%d %q %q %q", code, r.Method, r.URL.String(), message)
}

// HandleInquireContext accepts the context, unwraps, and then outputs its
// parameters obtained with InquireContext
func HandleInquireContext(w http.ResponseWriter, r *http.Request) (code int, message string) {
	ctx, code, message := allowed(w, r)
	if ctx == nil {
		return code, message
	}

	srcName, targetName, lifetimeRec, mechType, ctxFlags,
	locallyInitiated, open, err := ctx.InquireContext()
	if err != nil {
		return http.StatusInternalServerError, err.Error()
	}
	defer srcName.Release()
	defer targetName.Release()

	body := fmt.Sprintf("%q %q %v %q %x %v %v",
		srcName, targetName, lifetimeRec, mechType.DebugString(), ctxFlags,
		locallyInitiated, open)

	fmt.Printf("BODY: [%s]\n",body)

	w.Write([]byte(body))
	return http.StatusOK, "OK"
}


func Service() error {
	log.Printf("Starting service %q", ServiceName)

	nameBuf, err := gssapi.MakeBufferString(ServiceName)
	if err != nil {
		return err
	}

	defer nameBuf.Release()

	name, err := nameBuf.Name(gssapi.GSS_KRB5_NT_PRINCIPAL_NAME)
	if err != nil {
		return err
	}
	defer name.Release()

	cred, actualMechs, _, err := gssapi.AcquireCred(
		name,gssapi.GSS_C_INDEFINITE, gssapi.GSS_C_NO_OID_SET, gssapi.GSS_C_ACCEPT,
		)

	actualMechs.Release()
	if err != nil {
		return err
	}
	Credential = cred

	keytab := os.Getenv("KRB5_KTNAME")

	log.Printf("Acquired credentials using %v", keytab)

	http.Handle("/access/", loggingHandler{HandleAccess})
	http.Handle("/verify_mic/", loggingHandler{HandleVerifyMIC})
	http.Handle("/unwrap/", loggingHandler{HandleUnwrap})
	http.Handle("/inquire_context/", loggingHandler{HandleInquireContext})

	err = http.ListenAndServe(ServiceAddress, nil)
	if err != nil {
		return err
	}

	// this isn't executed since the entire container is killed, but for
	// illustration purposes
	Credential.Release()

	return nil
}

func HandleAccess(w http.ResponseWriter, r *http.Request) (code int, message string) {
	ctx, code, message := allowed(w, r)
	if ctx == nil {
		return code, message
	}
	w.Write([]byte("OK"))
	return http.StatusOK, "OK"
}

// allowed implements the SPNEGO protocol. When the request is to be passed
// through, it returns http.StatusOK and a valid gssapi CtxId object.
// Otherwise, it sets the WWW-Authorization header as applicable, and returns
// http.StatusUnathorized.
func allowed(w http.ResponseWriter, r *http.Request) (
	ctx *gssapi.CtxId, code int, message string) {

	log.Printf("Authorization: %s",r.Header.Get("Authorization"))

	// returning a 401 with a challenge, but no token will make the client
	// initiate security context and re-submit with a non-empty Authorization
	negotiate, inputToken := spnego.CheckSPNEGONegotiate(r.Header, "Authorization")
	if !negotiate || inputToken.Length() == 0 {
		spnego.AddSPNEGONegotiate(w.Header(), "WWW-Authenticate", nil)
		return nil, http.StatusUnauthorized, "no input token provided"
	}

	ctx, srcName, _, outputToken, _, _, delegatedCredHandle, err := gssapi.AcceptSecContext(
		gssapi.GSS_C_NO_CONTEXT, Credential, inputToken, gssapi.GSS_C_NO_CHANNEL_BINDINGS,
		)

	//TODO: special case handling of GSS_S_CONTINUE_NEEDED
	// but it doesn't change the logic, still fail
	if err != nil {
		//TODO: differentiate invalid tokens here and return a 403
		//TODO: add a test for a bad and maybe an expired auth tokens
		return nil, http.StatusInternalServerError, err.Error()
	}

	srcName.Release()
	delegatedCredHandle.Release()

	spnego.AddSPNEGONegotiate(w.Header(), "WWW-Authenticate", outputToken)
	return ctx, http.StatusOK, "pass"
}

// This test handler accepts the context, unwraps, and then re-wraps the request body
func HandleUnwrap(w http.ResponseWriter, r *http.Request) (code int, message string) {
	ctx, code, message := allowed(w, r)
	if ctx == nil {
		return code, message
	}

	// Unwrap the request
	wrappedbytes, err := ioutil.ReadAll(base64.NewDecoder(base64.StdEncoding, r.Body))
	if err != nil {
		return http.StatusInternalServerError, err.Error()
	}

	wrapped, err := gssapi.MakeBufferBytes(wrappedbytes)
	if err != nil {
		return http.StatusInternalServerError, err.Error()
	}
	defer wrapped.Release()

	unwrapped, _, _, err := ctx.Unwrap(wrapped)
	if err != nil {
		return http.StatusInternalServerError, err.Error()
	}
	defer unwrapped.Release()

	// Re-wrap the for the response
	_, wrapped, err = ctx.Wrap(true, gssapi.GSS_C_QOP_DEFAULT, unwrapped)
	if err != nil {
		return http.StatusInternalServerError, err.Error()
	}
	defer wrapped.Release()

	wrapped64 := base64.StdEncoding.EncodeToString(wrapped.Bytes())
	w.Write([]byte(wrapped64))
	return http.StatusOK, "OK"
}

func HandleVerifyMIC(w http.ResponseWriter, r *http.Request) (code int, message string) {
	ctx, code, message := allowed(w, r)
	if ctx == nil {
		return code, message
	}
	mic64 := r.Header.Get(micHeader)
	if mic64 == "" {
		return http.StatusInternalServerError, "No " + micHeader + " header"
	}
	micbytes, err := base64.StdEncoding.DecodeString(mic64)
	if err != nil {
		return http.StatusInternalServerError, err.Error()
	}
	mic, err := gssapi.MakeBufferBytes(micbytes)
	if err != nil {
		return http.StatusInternalServerError, err.Error()
	}
	bodybytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return http.StatusInternalServerError, err.Error()
	}
	body, err := gssapi.MakeBufferBytes(bodybytes)
	if err != nil {
		return http.StatusInternalServerError, err.Error()
	}
	_, err = ctx.VerifyMIC(body, mic)
	if err != nil {
		return http.StatusInternalServerError, err.Error()
	}
	w.Write([]byte("OK"))
	return http.StatusOK, "OK"
}
