package provider

import (
	"bytes"
	"crypto/md5"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/Dreamacro/clash/log"
)

var (
	fileMode os.FileMode = 0666
	dirMode  os.FileMode = 0755
)

type parser = func([]byte) (interface{}, error)

type fetcher struct {
	name        string
	vehicle     Vehicle
	tryUpdateAt *time.Time
	updatedAt   *time.Time
	interval    time.Duration
	signal      chan struct{}
	hash        [16]byte
	parser      parser
	closed      uint32
	onUpdate    func(interface{})
}

func (f *fetcher) Name() string {
	return f.name
}

func (f *fetcher) VehicleType() VehicleType {
	return f.vehicle.Type()
}

func (f *fetcher) Initial() (interface{}, error) {
	var (
		buf     []byte
		err     error
		isLocal bool
	)
	if stat, fErr := os.Stat(f.vehicle.Path()); fErr == nil {
		buf, err = ioutil.ReadFile(f.vehicle.Path())
		modTime := stat.ModTime()
		f.updatedAt = &modTime
		f.tryUpdateAt = f.updatedAt
		isLocal = true
	} else {
		buf, err = f.vehicle.Read()
	}

	if err != nil {
		return nil, err
	}

	proxies, err := f.parser(buf)
	if err != nil {
		if !isLocal {
			return nil, err
		}

		// parse local file error, fallback to remote
		buf, err = f.vehicle.Read()
		if err != nil {
			return nil, err
		}

		proxies, err = f.parser(buf)
		if err != nil {
			return nil, err
		}

		isLocal = false
	}

	if f.vehicle.Type() != File && !isLocal {
		if err := safeWrite(f.vehicle.Path(), buf); err != nil {
			return nil, err
		}
	}

	f.hash = md5.Sum(buf)

	// pull proxies automatically
	if f.interval > 0 {
		go f.pullLoop()
	}

	return proxies, nil
}

func (f *fetcher) Update() (interface{}, bool, error) {
	now := time.Now()
	f.tryUpdateAt = &now

	buf, err := f.vehicle.Read()
	if err != nil {
		return nil, false, err
	}

	now = time.Now()
	hash := md5.Sum(buf)
	if bytes.Equal(f.hash[:], hash[:]) {
		f.updatedAt = &now
		return nil, true, nil
	}

	proxies, err := f.parser(buf)
	if err != nil {
		return nil, false, err
	}

	if f.vehicle.Type() != File {
		if err := safeWrite(f.vehicle.Path(), buf); err != nil {
			return nil, false, err
		}
	}

	f.updatedAt = &now
	f.hash = hash

	f.notify()

	return proxies, false, nil
}

func (f *fetcher) Destroy() error {
	atomic.StoreUint32(&f.closed, 1)

	f.notify()

	return nil
}

func (f *fetcher) notify() {
	select {
	case f.signal <- struct{}{}:
		break
	default:
		break
	}
}

func (f *fetcher) pullLoop() {
	timer := time.NewTimer(f.interval)
	defer timer.Stop()

	for atomic.LoadUint32(&f.closed) == 0 {
		offset := f.interval - time.Since(*f.tryUpdateAt)

		if offset < 0 {
			offset = time.Second * 1
		}

		timer.Reset(offset)

		select {
		case <-timer.C:
			elm, same, err := f.Update()
			if err != nil {
				log.Warnln("[Provider] %s pull error: %s", f.Name(), err.Error())
				continue
			}

			if same {
				log.Debugln("[Provider] %s's proxies doesn't change", f.Name())
				continue
			}

			log.Infoln("[Provider] %s's proxies update", f.Name())
			if f.onUpdate != nil {
				f.onUpdate(elm)
			}
		case <-f.signal:
			continue
		}
	}
}

func safeWrite(path string, buf []byte) error {
	dir := filepath.Dir(path)

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, dirMode); err != nil {
			return err
		}
	}

	return ioutil.WriteFile(path, buf, fileMode)
}

func newFetcher(name string, interval time.Duration, vehicle Vehicle, parser parser, onUpdate func(interface{})) *fetcher {
	return &fetcher{
		name:     name,
		interval: interval,
		vehicle:  vehicle,
		parser:   parser,
		signal:   make(chan struct{}, 1),
		onUpdate: onUpdate,
	}
}
