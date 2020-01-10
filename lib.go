package gssapi

/*
#cgo linux LDFLAGS: -ldl -lpthread -lgssapi_krb5

#include <gssapi/gssapi.h>
#include <dlfcn.h>
#include <stdlib.h>

// Name-Types.  These are standardized in the RFCs.  The library requires that
// a given name be usable for resolution, but it's typically a macro, there's
// no guarantee about the name exported from the library.  But since they're
// static, and well-defined, we can just define them ourselves.

// RFC2744-mandated values, mapping from as-near-as-possible to cut&paste
const gss_OID_desc *_GSS_C_NT_USER_NAME           = & (gss_OID_desc) { 10, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x01" };
const gss_OID_desc *_GSS_C_NT_MACHINE_UID_NAME    = & (gss_OID_desc) { 10, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x02" };
const gss_OID_desc *_GSS_C_NT_STRING_UID_NAME     = & (gss_OID_desc) { 10, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x03" };
const gss_OID_desc *_GSS_C_NT_HOSTBASED_SERVICE_X = & (gss_OID_desc) {  6, "\x2b\x06\x01\x05\x06\x02" };
const gss_OID_desc *_GSS_C_NT_HOSTBASED_SERVICE   = & (gss_OID_desc) { 10, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x01\x04" };
const gss_OID_desc *_GSS_C_NT_ANONYMOUS           = & (gss_OID_desc) {  6, "\x2b\x06\x01\x05\x06\x03" };  // original had \01
const gss_OID_desc *_GSS_C_NT_EXPORT_NAME         = & (gss_OID_desc) {  6, "\x2b\x06\x01\x05\x06\x04" };

// from gssapi_krb5.h: This name form shall be represented by the Object
// Identifier {iso(1) member-body(2) United States(840) mit(113554) infosys(1)
// gssapi(2) krb5(2) krb5_name(1)}.  The recommended symbolic name for this
// type is "GSS_KRB5_NT_PRINCIPAL_NAME".
const gss_OID_desc *_GSS_KRB5_NT_PRINCIPAL_NAME   = & (gss_OID_desc) { 10, "\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x01" };

// { 1 2 840 113554 1 2 2 2 }
const gss_OID_desc *_GSS_KRB5_NT_PRINCIPAL         = & (gss_OID_desc) { 10, "\x2A\x86\x48\x86\xF7\x12\x01\x02\x02\x02" };

// known mech OIDs
const gss_OID_desc *_GSS_MECH_KRB5                 = & (gss_OID_desc) {  9, "\x2A\x86\x48\x86\xF7\x12\x01\x02\x02" };
const gss_OID_desc *_GSS_MECH_KRB5_LEGACY          = & (gss_OID_desc) {  9, "\x2A\x86\x48\x82\xF7\x12\x01\x02\x02" };
const gss_OID_desc *_GSS_MECH_KRB5_OLD             = & (gss_OID_desc) {  5, "\x2B\x05\x01\x05\x02" };
const gss_OID_desc *_GSS_MECH_SPNEGO               = & (gss_OID_desc) {  6, "\x2b\x06\x01\x05\x05\x02" };
const gss_OID_desc *_GSS_MECH_IAKERB               = & (gss_OID_desc) {  6, "\x2b\x06\x01\x05\x02\x05" };
const gss_OID_desc *_GSS_MECH_NTLMSSP              = & (gss_OID_desc) { 10, "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a" };
*/
import "C"

import "os"

// constants are a number of constant initialized in initConstants.
var (
	GSS_C_NO_BUFFER     *Buffer
	GSS_C_NO_OID        *OID
	GSS_C_NO_OID_SET    *OIDSet
	GSS_C_NO_CONTEXT    *CtxId
	GSS_C_NO_CREDENTIAL *CredId
	// when adding new OID constants also need to update OID.DebugString
	GSS_C_NT_USER_NAME           *OID
	GSS_C_NT_MACHINE_UID_NAME    *OID
	GSS_C_NT_STRING_UID_NAME     *OID
	GSS_C_NT_HOSTBASED_SERVICE_X *OID
	GSS_C_NT_HOSTBASED_SERVICE   *OID
	GSS_C_NT_ANONYMOUS           *OID
	GSS_C_NT_EXPORT_NAME         *OID
	GSS_KRB5_NT_PRINCIPAL_NAME   *OID
	GSS_KRB5_NT_PRINCIPAL        *OID
	GSS_MECH_KRB5                *OID
	GSS_MECH_KRB5_LEGACY         *OID
	GSS_MECH_KRB5_OLD            *OID
	GSS_MECH_SPNEGO              *OID
	GSS_MECH_IAKERB              *OID
	GSS_MECH_NTLMSSP             *OID
	GSS_C_NO_CHANNEL_BINDINGS    ChannelBindings // implicitly initialized as nil
)

func init()  {
	GSS_C_NO_BUFFER = &Buffer{
		// C_gss_buffer_t: C.GSS_C_NO_BUFFER, already nil
		// alloc: allocNone, already 0
	}
	GSS_C_NO_OID = NewOID()
	GSS_C_NO_OID_SET = NewOIDSet()
	GSS_C_NO_CONTEXT = NewCtxId()
	GSS_C_NO_CREDENTIAL = NewCredId()

	GSS_C_NT_USER_NAME = &OID{C_gss_OID: C._GSS_C_NT_USER_NAME}
	GSS_C_NT_MACHINE_UID_NAME = &OID{C_gss_OID: C._GSS_C_NT_MACHINE_UID_NAME}
	GSS_C_NT_STRING_UID_NAME = &OID{C_gss_OID: C._GSS_C_NT_MACHINE_UID_NAME}
	GSS_C_NT_HOSTBASED_SERVICE_X = &OID{C_gss_OID: C._GSS_C_NT_HOSTBASED_SERVICE_X}
	GSS_C_NT_HOSTBASED_SERVICE = &OID{C_gss_OID: C._GSS_C_NT_HOSTBASED_SERVICE}
	GSS_C_NT_ANONYMOUS = &OID{C_gss_OID: C._GSS_C_NT_ANONYMOUS}
	GSS_C_NT_EXPORT_NAME = &OID{C_gss_OID: C._GSS_C_NT_EXPORT_NAME}

	GSS_KRB5_NT_PRINCIPAL_NAME = &OID{C_gss_OID: C._GSS_KRB5_NT_PRINCIPAL_NAME}
	GSS_KRB5_NT_PRINCIPAL = &OID{C_gss_OID: C._GSS_KRB5_NT_PRINCIPAL}

	GSS_MECH_KRB5 = &OID{C_gss_OID: C._GSS_MECH_KRB5}
	GSS_MECH_KRB5_LEGACY = &OID{C_gss_OID: C._GSS_MECH_KRB5_LEGACY}
	GSS_MECH_KRB5_OLD = &OID{C_gss_OID: C._GSS_MECH_KRB5_OLD}
	GSS_MECH_SPNEGO = &OID{C_gss_OID: C._GSS_MECH_SPNEGO}
	GSS_MECH_IAKERB = &OID{C_gss_OID: C._GSS_MECH_IAKERB}
	GSS_MECH_NTLMSSP = &OID{C_gss_OID: C._GSS_MECH_NTLMSSP}
}

func Krb5Set(Krb5Config string, Krb5Ktname string) error {
	err := os.Setenv("KRB5_CONFIG", Krb5Config)
	if err != nil {
		return err
	}
	err = os.Setenv("KRB5_KTNAME", Krb5Ktname)
	if err != nil {
		return err
	}
	return nil
}
