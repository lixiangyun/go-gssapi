package gssapi

/*
#include <gssapi/gssapi.h>
*/
import "C"

import (
	"time"
)

// NewCredId instantiates a new credential.
func NewCredId() *CredId {
	return &CredId{}
}

// AcquireCred implements gss_acquire_cred API, as per
// https://tools.ietf.org/html/rfc2743#page-31. outputCredHandle, actualMechs
// must be .Release()-ed by the caller
func AcquireCred(desiredName *Name, timeReq time.Duration,
	desiredMechs *OIDSet, credUsage CredUsage) (outputCredHandle *CredId,
	actualMechs *OIDSet, timeRec time.Duration, err error) {

	min := C.OM_uint32(0)
	actualMechs = NewOIDSet()
	outputCredHandle = NewCredId()
	timerec := C.OM_uint32(0)

	maj := C.gss_acquire_cred(&min,
		desiredName.C_gss_name_t,
		C.OM_uint32(timeReq.Seconds()),
		desiredMechs.C_gss_OID_set,
		C.gss_cred_usage_t(credUsage),
		&outputCredHandle.C_gss_cred_id_t,
		&actualMechs.C_gss_OID_set,
		&timerec)

	err = StashLastStatus(maj, min)
	if err != nil {
		return nil, nil, 0, err
	}

	return outputCredHandle, actualMechs, time.Duration(timerec) * time.Second, nil
}

// AddCred implements gss_add_cred API, as per
// https://tools.ietf.org/html/rfc2743#page-36. outputCredHandle, actualMechs
// must be .Release()-ed by the caller
func AddCred(inputCredHandle *CredId,
	desiredName *Name, desiredMech *OID, credUsage CredUsage,
	initiatorTimeReq time.Duration, acceptorTimeReq time.Duration) (
	outputCredHandle *CredId, actualMechs *OIDSet,
	initiatorTimeRec time.Duration, acceptorTimeRec time.Duration,
	err error) {

	min := C.OM_uint32(0)
	actualMechs = NewOIDSet()
	outputCredHandle = NewCredId()
	initSeconds := C.OM_uint32(0)
	acceptSeconds := C.OM_uint32(0)

	maj := C.gss_add_cred(&min,
		inputCredHandle.C_gss_cred_id_t,
		desiredName.C_gss_name_t,
		desiredMech.C_gss_OID,
		C.gss_cred_usage_t(credUsage),
		C.OM_uint32(initiatorTimeReq.Seconds()),
		C.OM_uint32(acceptorTimeReq.Seconds()),
		&outputCredHandle.C_gss_cred_id_t,
		&actualMechs.C_gss_OID_set,
		&initSeconds,
		&acceptSeconds)

	err = StashLastStatus(maj, min)
	if err != nil {
		return nil, nil, 0, 0, err
	}

	return outputCredHandle,
		actualMechs,
		time.Duration(initSeconds) * time.Second,
		time.Duration(acceptSeconds) * time.Second,
		nil
}

// InquireCred implements gss_inquire_cred API, as per
// https://tools.ietf.org/html/rfc2743#page-34. name and mechanisms must be
// .Release()-ed by the caller
func InquireCred(credHandle *CredId) (
	name *Name, lifetime time.Duration, credUsage CredUsage, mechanisms *OIDSet,
	err error) {

	min := C.OM_uint32(0)
	name = NewName()
	life := C.OM_uint32(0)
	credUsage = CredUsage(0)
	mechanisms = NewOIDSet()

	maj := C.gss_inquire_cred(&min,
		credHandle.C_gss_cred_id_t,
		&name.C_gss_name_t,
		&life,
		(*C.gss_cred_usage_t)(&credUsage),
		&mechanisms.C_gss_OID_set)

	err = StashLastStatus(maj, min)
	if err != nil {
		return nil, 0, 0, nil, err
	}

	return name,
		time.Duration(life) * time.Second,
		credUsage,
		mechanisms,
		nil
}

// InquireCredByMech implements gss_inquire_cred_by_mech API, as per
// https://tools.ietf.org/html/rfc2743#page-39. name must be .Release()-ed by
// the caller
func InquireCredByMech(credHandle *CredId, mechType *OID) (
	name *Name, initiatorLifetime time.Duration, acceptorLifetime time.Duration,
	credUsage CredUsage, err error) {

	min := C.OM_uint32(0)
	name = NewName()
	ilife := C.OM_uint32(0)
	alife := C.OM_uint32(0)
	credUsage = CredUsage(0)

	maj := C.gss_inquire_cred_by_mech(
		&min,
		credHandle.C_gss_cred_id_t,
		mechType.C_gss_OID,
		&name.C_gss_name_t,
		&ilife,
		&alife,
		(*C.gss_cred_usage_t)(&credUsage))

	err = StashLastStatus(maj, min)
	if err != nil {
		return nil, 0, 0, 0, err
	}

	return name,
		time.Duration(ilife) * time.Second,
		time.Duration(alife) * time.Second,
		credUsage,
		nil
}

// Release frees a credential.
func (c *CredId) Release() error {
	if c == nil || c.C_gss_cred_id_t == nil {
		return nil
	}
	min := C.OM_uint32(0)
	maj := C.gss_release_cred(&min, &c.C_gss_cred_id_t)
	return StashLastStatus(maj, min)
}

//TODO: Test for AddCred with existing cred
