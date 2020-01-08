

package main

import (
	"flag"
	"log"
	gssapi "github.com/lixiangyun/go-gssapi"
)

var (
	ServiceName    string
	ServiceAddress string

	Krb5Ktname string
	Krb5Config string

	// Service credentials loaded from keytab
	Credential *gssapi.CredId
)

func init() {
	flag.StringVar(&ServiceName, "service-name", "SampleService", "service name")
	flag.StringVar(&ServiceAddress, "service-address", ":8080", "service address hostname:port")
	flag.StringVar(&Krb5Ktname, "krb5-ktname", "", "path to the keytab file")
	flag.StringVar(&Krb5Config, "krb5-config", "", "path to krb5.config file")
}

func main()  {
	flag.Parse()

	err := gssapi.Krb5Set(Krb5Config,Krb5Ktname)
	if err != nil {
		log.Fatal(err)
	}

	log.Fatal(Service())
}

func prepareServiceName() *gssapi.Name {
	nameBuf, err := gssapi.MakeBufferString(ServiceName)
	if err != nil {
		log.Fatal(err)
	}
	defer nameBuf.Release()
	name, err := nameBuf.Name(gssapi.GSS_KRB5_NT_PRINCIPAL_NAME)
	if err != nil {
		log.Fatal(err)
	}
	if name.String() != ServiceName {
		log.Fatalf("name: got %q, expected %q", name.String(), ServiceName)
	}
	return name
}