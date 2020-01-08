

//+build servicetest

package main

// test the credentials APIs with a keytab, configured against a real KDC

import (
	"strings"
	"time"

	gssapi "github.com/lixiangyun/go-gssapi"
)

func TestAcquireCredential() {
	name := prepareServiceName()
	defer name.Release()
	if name.String() != c.ServiceName {
		log.Fatalf("name: got %q, expected %q", name.String(), c.ServiceName)
	}

	mechs, err := c.MakeOIDSet(c.GSS_MECH_KRB5)
	if err != nil {
		log.Fatal(err)
	}
	defer mechs.Release()

	cred, actualMechs, timeRec, err := c.AcquireCred(name,
		gssapi.GSS_C_INDEFINITE, mechs, gssapi.GSS_C_ACCEPT)
	defer cred.Release()
	defer actualMechs.Release()
	verifyCred(t, cred, actualMechs, timeRec, err)
}

func TestAddCredential() {
	name := prepareServiceName()
	defer name.Release()
	if name.String() != c.ServiceName {
		t.Fatalf("name: got %q, expected %q", name.String(), c.ServiceName)
	}

	mechs, err := c.MakeOIDSet(c.GSS_MECH_KRB5)
	if err != nil {
		t.Fatal(err)
	}
	defer mechs.Release()

	cred := c.NewCredId()
	cred, actualMechs, _, acceptorTimeRec, err := c.AddCred(
		cred, name, c.GSS_MECH_KRB5, gssapi.GSS_C_ACCEPT,
		gssapi.GSS_C_INDEFINITE, gssapi.GSS_C_INDEFINITE)
	defer cred.Release()
	defer actualMechs.Release()
	verifyCred(cred, actualMechs, acceptorTimeRec, err)
}

func verifyCred(cred *gssapi.CredId, actualMechs *gssapi.OIDSet, timeRec time.Duration, err error) {

	if err != nil {
		log.Fatal(err)
	}
	if cred == nil {
		log.Fatal("Got nil cred, expected non-nil")
	}
	if actualMechs == nil {
		log.Fatal("Got nil actualMechs, expected non-nil")
	}
	contains, _ := actualMechs.TestOIDSetMember(c.GSS_MECH_KRB5)
	if !contains {
		log.Fatalf("Expected mechs to contain %q, got %q",
			c.GSS_MECH_KRB5.DebugString(),
			actualMechs.DebugString)
	}
	name, lifetime, credUsage, _, err := c.InquireCred(cred)
	if err != nil {
		log.Fatal(err)
	}
	parts := strings.Split(name.String(), "@")
	if len(parts) != 2 || parts[0] != c.ServiceName {
		log.Fatalf("name: got %q, expected %q", name.String(), c.ServiceName+"@<domain>")
	}
	if credUsage != gssapi.GSS_C_ACCEPT {
		log.Fatalf("credUsage: got %v, expected gssapi.GSS_C_ACCEPT", credUsage)
	}
	if timeRec != lifetime {
		log.Fatalf("timeRec:%v != lifetime:%v", timeRec, lifetime)
	}
}
