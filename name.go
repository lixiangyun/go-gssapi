package gssapi

// Side-note: gss_const_name_t is defined in RFC5587 as a bug-fix over RFC2744,
// since "const gss_name_t foo" says that the foo pointer is const, not the item
// pointed to is const.  Ideally, we'd be able to detect that, or have a macro
// which indicates availability of the 5587 extensions.  Instead, we're stuck with
// the ancient system GSSAPI headers on MacOS not supporting this.
//
// Choosing between "correctness" on the target platform and losing that for others,
// I've chosen to pull in /opt/local/include for MacPorts on MacOS; that should get
// us a functioning type; it's a pointer, at the ABI level the typing doesn't matter,
// so once we compile we're good.  If modern (correct) headers are available in other
// locations, just add them to the search path for the relevant OS below.
//
// Using "MacPorts" on MacOS gives us: -I/opt/local/include
// Using "brew" on MacOS gives us: -I/usr/local/opt/heimdal/include

/*
#include <stdio.h>
#include <gssapi/gssapi.h>
*/
import "C"

// NewName initializes a new principal name.
func NewName() *Name {
	return &Name{}
}

// GSS_C_NO_NAME is a Name where the value is NULL, used to request special
// behavior in some GSSAPI calls.
func GSS_C_NO_NAME() *Name {
	return NewName()
}

// Release frees the memory associated with an internal representation of the
// name.
func (n *Name) Release() error {
	if n == nil || n.C_gss_name_t == nil {
		return nil
	}
	var min C.OM_uint32
	maj := C.gss_release_name(&min, &n.C_gss_name_t)
	err := StashLastStatus(maj, min)
	if err == nil {
		n.C_gss_name_t = nil
	}
	return err
}

// Equal tests 2 names for semantic equality (refer to the same entity)
func (n Name) Equal(other Name) (equal bool, err error) {
	var min C.OM_uint32
	var isEqual C.int

	maj := C.gss_compare_name(&min, n.C_gss_name_t, other.C_gss_name_t, &isEqual)
	err = StashLastStatus(maj, min)
	if err != nil {
		return false, err
	}

	return isEqual != 0, nil
}

// Display "allows an application to obtain a textual representation of an
// opaque internal-form name for display purposes"
func (n Name) Display() (name string, oid *OID, err error) {
	var min C.OM_uint32
	b, err := MakeBuffer(allocGSSAPI)
	if err != nil {
		return "", nil, err
	}
	defer b.Release()

	oid = NewOID()
	maj := C.gss_display_name(&min, n.C_gss_name_t, b.C_gss_buffer_t, &oid.C_gss_OID)

	err = StashLastStatus(maj, min)
	if err != nil {
		oid.Release()
		return "", nil, err
	}

	return b.String(), oid, err
}

// String displays a Go-friendly version of a name. ("" on error)
func (n Name) String() string {
	s, _, _ := n.Display()
	return s
}

// Canonicalize returns a copy of this name, canonicalized for the specified
// mechanism
func (n Name) Canonicalize(mech_type *OID) (canonical *Name, err error) {
	canonical = NewName()

	var min C.OM_uint32
	maj := C.gss_canonicalize_name(&min,n.C_gss_name_t, mech_type.C_gss_OID, &canonical.C_gss_name_t)
	err = StashLastStatus(maj, min)
	if err != nil {
		return nil, err
	}

	return canonical, nil
}

// Duplicate creates a new independent imported name; after this, both the original and
// the duplicate will need to be .Released().
func (n *Name) Duplicate() (duplicate *Name, err error) {
	duplicate = NewName()

	var min C.OM_uint32
	maj := C.gss_duplicate_name(&min, n.C_gss_name_t, &duplicate.C_gss_name_t)
	err = StashLastStatus(maj, min)
	if err != nil {
		return nil, err
	}

	return duplicate, nil
}

// Export makes a text (Buffer) version from an internal representation
func (n *Name) Export() (b *Buffer, err error) {
	b, err = MakeBuffer(allocGSSAPI)
	if err != nil {
		return nil, err
	}

	var min C.OM_uint32
	maj := C.gss_export_name(&min, n.C_gss_name_t, b.C_gss_buffer_t)
	err = StashLastStatus(maj, min)
	if err != nil {
		b.Release()
		return nil, err
	}

	return b, nil
}

// InquireMechs returns the set of mechanisms supported by the GSS-API
// implementation that may be able to process the specified name
func (n *Name) InquireMechs() (oids *OIDSet, err error) {
	oidset := NewOIDSet()
	if err != nil {
		return nil, err
	}

	var min C.OM_uint32
	maj := C.gss_inquire_mechs_for_name(&min, n.C_gss_name_t, &oidset.C_gss_OID_set)
	err = StashLastStatus(maj, min)
	if err != nil {
		return nil, err
	}

	return oidset, nil
}

// InquireNameForMech returns the set of name types supported by
// the specified mechanism
func InquireNamesForMechs(mech *OID) (name_types *OIDSet, err error) {
	oidset := NewOIDSet()
	if err != nil {
		return nil, err
	}

	var min C.OM_uint32
	maj := C.gss_inquire_names_for_mech(&min, mech.C_gss_OID, &oidset.C_gss_OID_set)
	err = StashLastStatus(maj, min)
	if err != nil {
		return nil, err
	}

	return oidset, nil
}
