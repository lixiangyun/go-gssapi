package gssapi

/*
#include <gssapi/gssapi.h>

gss_OID
get_oid_set_member(
	gss_OID_set set,
	int index)
{
	return &(set->elements[index]);
}

*/
import "C"

import (
	"fmt"
	"strings"
)

// NewOIDSet constructs a new empty OID set.
func NewOIDSet() *OIDSet {
	return &OIDSet{
		// C_gss_OID_set: (C.gss_OID_set)(unsafe.Pointer(nil)),
	}
}

// MakeOIDSet makes an OIDSet prepopulated with the given OIDs.
func MakeOIDSet(oids ...*OID) (s *OIDSet, err error) {
	s = &OIDSet{}

	var min C.OM_uint32
	maj := C.gss_create_empty_oid_set(&min, &s.C_gss_OID_set)
	err = StashLastStatus(maj, min)
	if err != nil {
		return nil, err
	}

	err = s.Add(oids...)
	if err != nil {
		return nil, err
	}

	return s, nil
}

// Release frees all C memory associated with an OIDSet.
func (s *OIDSet) Release() (err error) {
	if s == nil || s.C_gss_OID_set == nil {
		return nil
	}

	var min C.OM_uint32
	maj := C.gss_release_oid_set(&min, &s.C_gss_OID_set)
	return StashLastStatus(maj, min)
}

// Add adds OIDs to an OIDSet.
func (s *OIDSet) Add(oids ...*OID) (err error) {
	var min C.OM_uint32
	for _, oid := range oids {
		maj := C.gss_add_oid_set_member(&min, oid.C_gss_OID, &s.C_gss_OID_set)
		err = StashLastStatus(maj, min)
		if err != nil {
			return err
		}
	}

	return nil
}

// TestOIDSetMember a wrapper to determine if an OIDSet contains an OID.
func (s *OIDSet) TestOIDSetMember(oid *OID) (contains bool, err error) {
	var min C.OM_uint32
	var isPresent C.int

	maj := C.gss_test_oid_set_member(&min, oid.C_gss_OID, s.C_gss_OID_set, &isPresent)
	err = StashLastStatus(maj, min)
	if err != nil {
		return false, err
	}

	return isPresent != 0, nil
}

// Contains (gss_test_oid_set_member) checks if an OID is present OIDSet.
func (s *OIDSet) Contains(oid *OID) bool {
	contains, _ := s.TestOIDSetMember(oid)
	return contains
}

// Length returns the number of OIDs in a set.
func (s *OIDSet) Length() int {
	if s == nil {
		return 0
	}
	return int(s.C_gss_OID_set.count)
}

// Get returns a specific OID from the set. The memory will be released when the
// set itself is released.
func (s *OIDSet) Get(index int) (*OID, error) {
	if s == nil || index < 0 || index >= int(s.C_gss_OID_set.count) {
		return nil, fmt.Errorf("index %d out of bounds", index)
	}
	oid := NewOID()
	oid.C_gss_OID = C.get_oid_set_member(s.C_gss_OID_set, C.int(index))
	return oid, nil
}

func (s *OIDSet) DebugString() string {
	names := make([]string, 0)
	for i := 0; i < s.Length(); i++ {
		oid, _ := s.Get(i)
		names = append(names, oid.DebugString())
	}
	return "[" + strings.Join(names, ", ") + "]"
}
