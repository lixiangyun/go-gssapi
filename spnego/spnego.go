package spnego

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	gssapi "github.com/lixiangyun/go-gssapi"
)

const (
	NEGOTIATE = "Negotiate"
	AUTH_HEAD = "Authorization"
	WWW_AUTH_HEAD = "WWW-Authenticate"
)

type SPNEGO struct {
	Cerd *gssapi.CredId
}

func NewSPNEGO(username string) (*SPNEGO, error) {

	name ,err := PrepareServiceName(username)
	if err != nil {
		return nil,err
	}
	defer name.Release()

	clientCred, actualMechs1, _, err := gssapi.AcquireCred(
		name, 0, gssapi.GSS_C_NO_OID_SET, gssapi.GSS_C_BOTH,
	)
	defer actualMechs1.Release()

	if err != nil {
		return nil,err
	}

	return &SPNEGO{Cerd:clientCred},nil
}

func (this *SPNEGO)Release() {
	this.Cerd.Release()
}

func (this *SPNEGO)NegotiateAddition(req http.Header, spname *gssapi.Name ) error {

	ctx, _, token, _, _, err := gssapi.InitSecContext(
		this.Cerd, gssapi.GSS_C_NO_CONTEXT, spname, gssapi.GSS_C_NO_OID,
		0,0,gssapi.GSS_C_NO_CHANNEL_BINDINGS,gssapi.GSS_C_NO_BUFFER)

	defer token.Release()

	if err != nil {

		e, ok := err.(*gssapi.Error)
		if ok && e.Major.ContinueNeeded() {
			return errors.New("Unexpected GSS_S_CONTINUE_NEEDED")
		}
		return err
	}

	//ctx.InquireContext()
	defer ctx.Release()

	if token.Length() == 0 {
		return errors.New("Unexpected Negotiate Token Null")
	}

	addSPNEGONegotiate(req, AUTH_HEAD, token)

	return nil
}

// Negotiate handles the SPNEGO client-server negotiation. Negotiate will likely
// be invoked multiple times; a 200 or 400 response code are terminating
// conditions, whereas a 401 means that the client should respond to the
// challenge that we send.
func (this *SPNEGO)NegotiateVerification(inHeader, outHeader http.Header) (string, int, error) {
	inputToken, err := checkSPNEGONegotiate(inHeader, AUTH_HEAD)
	defer inputToken.Release()

	// Here, challenge the client to initiate the security context. The first
	// request a client has made will often be unauthenticated, so we return a
	// 401, which the client handles.
	if err != nil || inputToken.Length() == 0 {
		addSPNEGONegotiate(outHeader, WWW_AUTH_HEAD, inputToken)
		return "", http.StatusUnauthorized, err
	}

	// FIXME: GSS_S_CONTINUED_NEEDED handling?
	ctx, srcName, _, outputToken, _, _, delegatedCredHandle, err :=
		gssapi.AcceptSecContext(gssapi.GSS_C_NO_CONTEXT, this.Cerd, inputToken, gssapi.GSS_C_NO_CHANNEL_BINDINGS)

	if err != nil {
		return "", http.StatusBadRequest, err
	}

	delegatedCredHandle.Release()
	ctx.Release()
	defer outputToken.Release()
	defer srcName.Release()

	addSPNEGONegotiate(outHeader, WWW_AUTH_HEAD, outputToken)
	return srcName.String(), http.StatusOK, nil
}

// AddSPNEGONegotiate adds a Negotiate header with the value of a serialized
// token to an http header.
func addSPNEGONegotiate(h http.Header, name string, token *gssapi.Buffer) {
	if token.Length() != 0 {
		data := token.Bytes()
		value := fmt.Sprintf(NEGOTIATE + " %s",base64.StdEncoding.EncodeToString(data) )
		h.Set(name, value )
	}else {
		h.Set(name, NEGOTIATE)
	}
}

// CheckSPNEGONegotiate checks for the presence of a Negotiate header. If
// present, we return a gssapi Token created from the header value sent to us.
func checkSPNEGONegotiate(h http.Header, name string) ( *gssapi.Buffer, error ) {
	v := h.Get(name)
	if len(v) == 0 || !strings.HasPrefix(v, NEGOTIATE) {
		errInfo := fmt.Sprintf("check spnego negotiate failed! [%s:%s]",name,v)
		return nil,errors.New(errInfo)
	}

	tbytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(v[len(NEGOTIATE):]))
	if err != nil {
		return nil,err
	}

	if len(tbytes) == 0 {
		return nil,errors.New("decode token lenght is null.")
	}

	token, err := gssapi.MakeBufferBytes(tbytes)
	if err != nil {
		return nil,err
	}

	return token,nil
}

func PrepareServiceName(svc string) (*gssapi.Name,error) {
	nameBuf, err := gssapi.MakeBufferString(svc)
	if err != nil {
		return nil,err
	}
	defer nameBuf.Release()
	name, err := nameBuf.Name(gssapi.GSS_KRB5_NT_PRINCIPAL_NAME)
	if err != nil {
		return nil,err
	}
	if name.String() != svc {
		defer name.Release()
		return nil,errors.New(fmt.Sprintf("name: got %q, expected %q", name.String(), svc))
	}
	return name,nil
}

func VerifyInquireContextResult(result string, regexps []string) error {
	rr := strings.Split(result, " ")
	if len(rr) != len(regexps) {
		errinfo := fmt.Sprintf("got %v fragments, expected %v (%s)", len(rr), len(regexps), result)
		return errors.New(errinfo)
	}

	for i, r := range rr {
		rx := regexp.MustCompile(regexps[i])
		if !rx.MatchString(r) {
			errinfo := fmt.Sprintf("%s does not match %s", r, regexps[i])
			return errors.New(errinfo)
		}
	}
	return nil
}

func CheckInquireContext(ctx *gssapi.CtxId) error {
	srcName, targetName, lifetimeRec, mechType, ctxFlags, locallyInitiated, open, err := ctx.InquireContext()
	if err != nil {
		return err
	}
	defer srcName.Release()
	defer targetName.Release()

	body := fmt.Sprintf("%q %q %v %q %x %v %v",
		srcName, targetName, lifetimeRec, mechType.DebugString(), ctxFlags,
		locallyInitiated, open)

	return VerifyInquireContextResult(body, []string{
		`"[a-zA-Z_-]+@[[:graph:]]+"`,
		`"HTTP/[[:graph:]]+@[[:graph:]]+"`,
		`[0-9a-z]+`,
		`[A-Z]+`,
		"1b0",
		"true",
		"true"})
}