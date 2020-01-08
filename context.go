package gssapi

// This file provides GSSContext methods

/*
#include <gssapi/gssapi.h>
*/
import "C"

import (
	"runtime"
	"time"
)

func NewCtxId() *CtxId {
	return &CtxId{}
}

// InitSecContext initiates a security context. Usually invoked by the client.
// A Context (CtxId) describes the state at one end of an authentication
// protocol. May return ErrContinueNeeded if the client is to make another
// iteration of exchanging token with the service
func InitSecContext(initiatorCredHandle *CredId, ctxIn *CtxId,
	targetName *Name, mechType *OID, reqFlags uint32, timeReq time.Duration,
	inputChanBindings ChannelBindings, inputToken *Buffer) (
	ctxOut *CtxId, actualMechType *OID, outputToken *Buffer, retFlags uint32,
	timeRec time.Duration, err error) {

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// prepare the input params
	C_initiator := C.gss_cred_id_t(nil)
	if initiatorCredHandle != nil {
		C_initiator = initiatorCredHandle.C_gss_cred_id_t
	}

	C_mechType := C.gss_OID(nil)
	if mechType != nil {
		C_mechType = mechType.C_gss_OID
	}

	C_inputToken := C.gss_buffer_t(nil)
	if inputToken != nil {
		C_inputToken = inputToken.C_gss_buffer_t
	}

	// prepare the outputs.
	if ctxIn != nil {
		ctxCopy := *ctxIn
		ctxOut = &ctxCopy
	} else {
		ctxOut = NewCtxId()
	}

	min := C.OM_uint32(0)
	actualMechType = NewOID()
	outputToken, err = MakeBuffer(allocGSSAPI)
	if err != nil {
		return nil, nil, nil, 0, 0, err
	}

	flags := C.OM_uint32(0)
	timerec := C.OM_uint32(0)

	maj := C.gss_init_sec_context(  &min,
									C_initiator,
									&ctxOut.C_gss_ctx_id_t, // used as both in and out param
									targetName.C_gss_name_t,
									C_mechType,
									C.OM_uint32(reqFlags),
									C.OM_uint32(timeReq.Seconds()),
									C.gss_channel_bindings_t(inputChanBindings),
									C_inputToken,
									&actualMechType.C_gss_OID,
									outputToken.C_gss_buffer_t,
									&flags,
									&timerec)
	err = StashLastStatus(maj, min)
	if err != nil {
		return nil, nil, nil, 0, 0, err
	}

	if MajorStatus(maj).ContinueNeeded() {
		err = ErrContinueNeeded
	}

	return ctxOut, actualMechType, outputToken,
		uint32(flags), time.Duration(timerec) * time.Second,
		err
}

// AcceptSecContext accepts an initialized security context. Usually called by
// the server. May return ErrContinueNeeded if the client is to make another
// iteration of exchanging token with the service
func AcceptSecContext(
	ctxIn *CtxId, acceptorCredHandle *CredId, inputToken *Buffer,
	inputChanBindings ChannelBindings) (
	ctxOut *CtxId, srcName *Name, actualMechType *OID, outputToken *Buffer,
	retFlags uint32, timeRec time.Duration, delegatedCredHandle *CredId,
	err error) {

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// prepare the inputs
	C_acceptorCredHandle := C.gss_cred_id_t(nil)
	if acceptorCredHandle != nil {
		C_acceptorCredHandle = acceptorCredHandle.C_gss_cred_id_t
	}

	C_inputToken := C.gss_buffer_t(nil)
	if inputToken != nil {
		C_inputToken = inputToken.C_gss_buffer_t
	}

	// prepare the outputs
	if ctxIn != nil {
		ctxCopy := *ctxIn
		ctxOut = &ctxCopy
	} else {
		ctxOut = GSS_C_NO_CONTEXT
	}

	min := C.OM_uint32(0)
	srcName = NewName()
	actualMechType = NewOID()
	outputToken, err = MakeBuffer(allocGSSAPI)
	if err != nil {
		return nil, nil, nil, nil, 0, 0, nil, err
	}
	flags := C.OM_uint32(0)
	timerec := C.OM_uint32(0)
	delegatedCredHandle = NewCredId()

	maj := C.gss_accept_sec_context(
		&min,
		&ctxOut.C_gss_ctx_id_t, // used as both in and out param
		C_acceptorCredHandle,
		C_inputToken,
		C.gss_channel_bindings_t(inputChanBindings),
		&srcName.C_gss_name_t,
		&actualMechType.C_gss_OID,
		outputToken.C_gss_buffer_t,
		&flags,
		&timerec,
		&delegatedCredHandle.C_gss_cred_id_t)

	err = StashLastStatus(maj, min)
	if err != nil {
		return nil, nil, nil, nil, 0, 0, nil, err
	}

	if MajorStatus(maj).ContinueNeeded() {
		err = ErrContinueNeeded
	}

	return ctxOut, srcName, actualMechType, outputToken, uint32(flags),
		time.Duration(timerec) * time.Second, delegatedCredHandle, err
}

// DeleteSecContext frees a security context.
// NB: I decided not to implement the outputToken parameter since its use is no
// longer recommended, and it would have to be Released by the caller
func (ctx *CtxId) DeleteSecContext() error {
	if ctx == nil || ctx.C_gss_ctx_id_t == nil {
		return nil
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	min := C.OM_uint32(0)
	maj := C.gss_delete_sec_context(&min, &ctx.C_gss_ctx_id_t, nil)

	return StashLastStatus(maj, min)
}

// Release is an alias for DeleteSecContext.
func (ctx *CtxId) Release() error {
	return ctx.DeleteSecContext()
}

// InquireContext returns fields about a security context.
func (ctx *CtxId) InquireContext() (
	srcName *Name, targetName *Name, lifetimeRec time.Duration, mechType *OID,
	ctxFlags uint64, locallyInitiated bool, open bool, err error) {

	min := C.OM_uint32(0)
	srcName = NewName()
	targetName = NewName()
	rec := C.OM_uint32(0)
	mechType = NewOID()
	flags := C.OM_uint32(0)
	li := C.int(0)
	opn := C.int(0)

	maj := C.gss_inquire_context( &min, ctx.C_gss_ctx_id_t,
								&srcName.C_gss_name_t,
								&targetName.C_gss_name_t,
								&rec,
								&mechType.C_gss_OID,
								&flags, &li, &opn)

	err = StashLastStatus(maj, min)
	if err != nil {
		return nil, nil, 0, nil, 0, false, false, err
	}

	lifetimeRec = time.Duration(rec) * time.Second
	ctxFlags = uint64(flags)

	if li != 0 {
		locallyInitiated = true
	}
	if opn != 0 {
		open = true
	}

	return srcName, targetName, lifetimeRec, mechType, ctxFlags, locallyInitiated, open, nil
}
