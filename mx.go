package send

import (
	"fmt"
	"strings"
	"sync"

	"github.com/monopolly/file"
)

func NewMX(filename string) (a *MX) {
	a = new(MX)
	a.filename = filename
	a.db = make(map[string]*mxrecord)
	a.load()
	return
}

type mxrecord struct {
	Domain  string   `json:"domain"` //gmail.com
	Servers []string `json:"servers"`
	Port    int      `json:"port"`
}

type MX struct {
	db map[string]*mxrecord
	sync.RWMutex
	filename string
}

func (a *MX) load() {
	logs("mx", "load")
	file.LoadJson(a.filename, &a.db)
}
func (a *MX) save() {
	logs("mx", "save")
	file.Json(a.filename, a.db)
}

func (a *MX) Set(domain string, servers []string, port ...int) {

	domain = strings.ToLower(domain)
	domain = strings.TrimSpace(domain)
	domain = strings.TrimSuffix(domain, ".")

	b := new(mxrecord)
	b.Domain = domain
	if port != nil {
		b.Port = port[0]
	}

	b.Servers = servers
	a.Lock()
	a.db[domain] = b
	a.Unlock()

	a.save()
}

func (a *MX) Get(domain string, reset ...bool) (servers []string, port int) {
	domain = strings.ToLower(domain)
	domain = strings.TrimSpace(domain)

	v := a.db[domain]
	logs("cache", v)
	if v == nil {
		logs("mx", "no cache")
		servers = mxservers(domain)
		a.Set(domain, servers)
		return
	}

	if v.Servers == nil {
		logs("mx", "no cache")
		servers = mxservers(domain)
		a.Set(domain, servers)
		return
	}

	return v.Servers, v.Port
}

func (a *MX) getTest(domain string, reset ...bool) (servers []string, port int) {
	domain = strings.ToLower(domain)
	domain = strings.TrimSpace(domain)

	fmt.Println("mx", "get", domain)

	v := a.db[domain]
	if v == nil {
		fmt.Println("mx", "no cache")
		servers = mxservers(domain)
		fmt.Println("mx", "servers", servers)
		a.Set(domain, servers)
		return
	}

	return v.Servers, v.Port
}
