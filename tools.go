package send

import (
	"net"
	"strings"
)

func domainonly(email string) (domain string) {
	_, after, ok := strings.Cut(email, "@")
	if !ok {
		return email
	}
	return after
}

func mxservers(domain string) (servers []string) {
	logs("mx", "get")
	mxrecords, _ := net.LookupMX(domain)
	logs("mx", mxrecords)
	for _, mx := range mxrecords {
		host := strings.TrimSuffix(mx.Host, ".")
		servers = append(servers, host)
	}
	return
}
