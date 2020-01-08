package gssapi

/*
#include <gssapi/gssapi.h>
*/
import "C"

// GetMIC implements gss_GetMIC API, as per https://tools.ietf.org/html/rfc2743#page-63.
// messageToken must be .Release()-ed by the caller.
func (ctx *CtxId) GetMIC(qopReq QOP, messageBuffer *Buffer) (
	messageToken *Buffer, err error) {

	min := C.OM_uint32(0)

	token, err := MakeBuffer(allocGSSAPI)
	if err != nil {
		return nil, err
	}

	maj := C.gss_get_mic(&min,
		ctx.C_gss_ctx_id_t,
		C.gss_qop_t(qopReq),
		messageBuffer.C_gss_buffer_t,
		token.C_gss_buffer_t)

	err = StashLastStatus(maj, min)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// VerifyMIC implements gss_VerifyMIC API, as per https://tools.ietf.org/html/rfc2743#page-64.
func (ctx *CtxId) VerifyMIC(messageBuffer *Buffer, tokenBuffer *Buffer) (
	qopState QOP, err error) {

	min := C.OM_uint32(0)
	qop := C.gss_qop_t(0)

	maj := C.gss_verify_mic(&min,
		ctx.C_gss_ctx_id_t,
		messageBuffer.C_gss_buffer_t,
		tokenBuffer.C_gss_buffer_t,
		&qop)

	err = StashLastStatus(maj, min)
	if err != nil {
		return 0, err
	}

	return QOP(qop), nil
}

// Wrap implements gss_wrap API, as per https://tools.ietf.org/html/rfc2743#page-65.
// outputMessageBuffer must be .Release()-ed by the caller
func (ctx *CtxId) Wrap(confReq bool, qopReq QOP, inputMessageBuffer *Buffer) (
	confState bool, outputMessageBuffer *Buffer, err error) {

	min := C.OM_uint32(0)

	encrypt := C.int(0)
	if confReq {
		encrypt = 1
	}

	outputMessageBuffer, err = MakeBuffer(allocGSSAPI)
	if err != nil {
		return false, nil, err
	}

	encrypted := C.int(0)

	maj := C.gss_wrap(&min,
		ctx.C_gss_ctx_id_t,
		encrypt,
		C.gss_qop_t(qopReq),
		inputMessageBuffer.C_gss_buffer_t,
		&encrypted,
		outputMessageBuffer.C_gss_buffer_t)

	err = StashLastStatus(maj, min)
	if err != nil {
		return false, nil, err
	}

	return encrypted != 0,
		outputMessageBuffer,
		nil
}

// Unwrap implements gss_unwrap API, as per https://tools.ietf.org/html/rfc2743#page-66.
// outputMessageBuffer must be .Release()-ed by the caller
func (ctx *CtxId) Unwrap(
	inputMessageBuffer *Buffer) (
	outputMessageBuffer *Buffer, confState bool, qopState QOP, err error) {

	min := C.OM_uint32(0)

	outputMessageBuffer, err = MakeBuffer(allocGSSAPI)
	if err != nil {
		return nil, false, 0, err
	}

	encrypted := C.int(0)
	qop := C.gss_qop_t(0)

	maj := C.gss_unwrap(&min,
		ctx.C_gss_ctx_id_t,
		inputMessageBuffer.C_gss_buffer_t,
		outputMessageBuffer.C_gss_buffer_t,
		&encrypted,
		&qop)

	err = StashLastStatus(maj, min)
	if err != nil {
		return nil, false, 0, err
	}

	return outputMessageBuffer,
		encrypted != 0,
		QOP(qop),
		nil
}
