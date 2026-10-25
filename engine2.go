package send

import (
	"log"
	"path/filepath"
)

func NewEngine2(r *Settings) (a *Engine2) {
	a = new(Engine2)
	a.Settings = r
	a.Settings.createSigner()
	a.mx = NewMX(filepath.Join(r.Volume, "mx.json"))
	a.err = r.Err
	if a.err == nil {
		a.err = func(err error) {
			log.Println(err)
		}
	}
	return
}

type Engine2 struct {
	*Settings
	err func(err error)
}
