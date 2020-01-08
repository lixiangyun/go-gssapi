package gssapi

/*
#include <gssapi/gssapi.h>
#include <stdlib.h>
*/
import "C"

// IndicateMechs implements the gss_Indicate_mechs call, according to https://tools.ietf.org/html/rfc2743#page-69.
// This returns an OIDSet of the Mechs supported on the current OS.
func IndicateMechs() (*OIDSet, error) {
	mechs := NewOIDSet()
	var min C.OM_uint32

	maj := C.gss_indicate_mechs(&min, &mechs.C_gss_OID_set)
	err := StashLastStatus(maj, min)
	if err != nil {
		return nil, err
	}

	return mechs, nil
}
