package main

import (
	"flag"
	"github.com/lixiangyun/go-gssapi"
	"github.com/lixiangyun/go-gssapi/spnego"
	"log"
	"os"
)

var (
	IsClient bool
	ClientName string

	ServiceName    string
	ServiceAddress string

	Krb5Ktname string
	Krb5Config string

	Help bool

	Spnego *spnego.SPNEGO
)

func init() {
	flag.BoolVar(&Help,"help",false,"usage help.")

	flag.BoolVar(&IsClient,"client",false,"client mode.")
	flag.StringVar(&ClientName,"client-name","","client name.")

	flag.StringVar(&ServiceName, "service-name", "", "service name")
	flag.StringVar(&ServiceAddress, "service-address", ":8080", "service address [hostname:port]")

	flag.StringVar(&Krb5Ktname, "krb5-ktname", "", "path to the keytab file")
	flag.StringVar(&Krb5Config, "krb5-config", "", "path to krb5.config file")
}

func main()  {
	flag.Parse()
	if Help || (IsClient && ClientName == "") || ServiceName == "" {
		flag.Usage()
		os.Exit(1)
	}

	err := gssapi.Krb5Set(Krb5Config,Krb5Ktname)
	if err != nil {
		log.Fatalln(err.Error())
	}

	if IsClient {
		Spnego, err = spnego.NewSPNEGO(ClientName)
		if err != nil {
			log.Fatalln(err.Error())
		}
		log.Printf("new spnego success! %v",Spnego)
		log.Fatal(Client(ServiceName,ServiceAddress,"POST","/abc",nil))
	}else {
		Spnego, err = spnego.NewSPNEGO(ServiceName)
		if err != nil {
			log.Fatalln(err.Error())
		}
		log.Printf("new spnego success! %v",Spnego)
		log.Fatal(Service())
	}
}