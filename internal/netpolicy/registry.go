package netpolicy

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/petrichor/21pins-cli/internal/policy"
)

const maxStateBytes = 16 << 20

// ponytail: one atomic JSON snapshot; no database or mutable graph service.
type registryState struct {
	Schema  int      `json:"schema"`
	Objects []Object `json:"objects"`
}
type Registry struct{ Path string }

func NewRegistry(path string) *Registry { return &Registry{Path: path} }
func stringPort(p uint16) string        { return strconv.FormatUint(uint64(p), 10) }

func readSafe(path string, dst any) error {
	before, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0600 || before.Size() > maxStateBytes {
		return ErrUnsafe
	}
	f, e := os.Open(path)
	if e != nil {
		return ErrUnsafe
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) || !after.Mode().IsRegular() {
		return ErrUnsafe
	}
	d := json.NewDecoder(io.LimitReader(f, maxStateBytes+1))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return ErrInvalid
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrInvalid
	}
	return nil
}
func (r *Registry) load() (registryState, error) {
	var s registryState
	e := readSafe(r.Path, &s)
	if os.IsNotExist(e) {
		return registryState{Schema: 1}, nil
	}
	if e != nil {
		return s, e
	}
	if s.Schema != 1 {
		return s, ErrInvalid
	}
	if e = validateObjects(s.Objects); e != nil {
		return s, e
	}
	return s, nil
}
func validateObjects(objects []Object) error {
	refs := map[string]bool{}
	aliases := map[string]bool{}
	endpoints := map[string]bool{}
	for _, o := range objects {
		if !validObject(o) || !strings.HasPrefix(o.Ref.ID, "net_") || o.Ref.Revision == 0 || refs[o.Ref.ID] {
			return ErrInvalid
		}
		key := string(o.Kind) + ":" + o.Alias
		if aliases[key] {
			return ErrConflict
		}
		aliases[key] = true
		refs[o.Ref.ID] = true
		if o.Kind == Service {
			k := o.Binding.Realm + "|" + o.Binding.Target + "|" + stringPort(o.Binding.Port)
			if endpoints[k] {
				return ErrConflict
			}
			endpoints[k] = true
		}
	}
	return nil
}
func atomicJSON(path string, v any) error {
	data, e := json.Marshal(v)
	if e != nil {
		return ErrInvalid
	}
	dir := filepath.Dir(path)
	f, e := os.CreateTemp(dir, ".network-tmp-")
	if e != nil {
		return ErrUnsafe
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e == nil {
		e = os.Rename(name, path)
	}
	if e != nil {
		return ErrUnsafe
	}
	d, e := os.Open(dir)
	if e != nil {
		return ErrUnsafe
	}
	defer d.Close()
	if d.Sync() != nil {
		return ErrUnsafe
	}
	return nil
}
func (r *Registry) mutate(fn func(*registryState) error) error {
	dir := filepath.Dir(r.Path)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return ErrUnsafe
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return ErrUnsafe
	}
	unlock, e := lockFile(r.Path + ".lock")
	if e != nil {
		return e
	}
	defer unlock()
	s, e := r.load()
	if e != nil {
		return e
	}
	if e = fn(&s); e != nil {
		return e
	}
	if e = validateObjects(s.Objects); e != nil {
		return e
	}
	return atomicJSON(r.Path, s)
}
func (r *Registry) Objects() ([]Object, error) { s, e := r.load(); return s.Objects, e }
func find(objects []Object, kind Kind, name string) (Object, error) {
	for _, o := range objects {
		if o.Kind == kind && (o.Alias == name || o.Ref.ID == name) {
			return o, nil
		}
	}
	return Object{}, ErrMissing
}
func (r *Registry) Resolve(kind Kind, name string) (Object, error) {
	s, e := r.load()
	if e != nil {
		return Object{}, e
	}
	return find(s.Objects, kind, name)
}
func (r *Registry) ResolveRef(ref Ref) (Object, error) {
	objects, e := r.Objects()
	if e != nil {
		return Object{}, e
	}
	for _, o := range objects {
		if o.Ref.ID == ref.ID {
			if o.Ref != ref {
				return Object{}, ErrStale
			}
			return o, nil
		}
	}
	return Object{}, ErrMissing
}
func bindRefs(objects []Object, b *Binding) error {
	for _, pair := range []struct {
		ref  *Ref
		kind Kind
	}{{&b.Gateway, Gateway}, {&b.VPN, VPN}, {&b.Source, Network}} {
		if pair.ref.ID == "" {
			continue
		}
		o, e := find(objects, pair.kind, pair.ref.ID)
		if e != nil {
			return e
		}
		if pair.ref.Revision != 0 && pair.ref.Revision != o.Ref.Revision {
			return ErrStale
		}
		*pair.ref = o.Ref
	}
	return nil
}
func (r *Registry) Create(o Object) (Object, error) {
	var result Object
	e := r.mutate(func(s *registryState) error {
		if o.Ref.ID != "" || o.Ref.Revision != 0 {
			return ErrInvalid
		}
		o.Ref = Ref{policy.NewID("net"), 1}
		if e := bindRefs(s.Objects, &o.Binding); e != nil {
			return e
		}
		s.Objects = append(s.Objects, o)
		result = o
		return nil
	})
	return result, e
}
func (r *Registry) Rename(kind Kind, name, alias string) (Object, error) {
	return r.change(kind, name, func(o *Object) { o.Alias = alias })
}
func (r *Registry) Rebind(kind Kind, name string, b Binding) (Object, error) {
	return r.change(kind, name, func(o *Object) { o.Binding = b; o.Ref.Revision++ })
}
func (r *Registry) change(kind Kind, name string, fn func(*Object)) (Object, error) {
	var result Object
	e := r.mutate(func(s *registryState) error {
		for i := range s.Objects {
			if s.Objects[i].Kind == kind && (s.Objects[i].Alias == name || s.Objects[i].Ref.ID == name) {
				fn(&s.Objects[i])
				if e := bindRefs(s.Objects, &s.Objects[i].Binding); e != nil {
					return e
				}
				result = s.Objects[i]
				return nil
			}
		}
		return ErrMissing
	})
	return result, e
}
func (r *Registry) Import(reader io.Reader) error {
	var input struct {
		Objects []Object `json:"objects"`
	}
	d := json.NewDecoder(io.LimitReader(reader, maxStateBytes))
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil {
		return ErrInvalid
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return ErrInvalid
	}
	return r.mutate(func(s *registryState) error {
		start := len(s.Objects)
		for _, o := range input.Objects {
			if o.Ref.ID != "" || o.Ref.Revision != 0 {
				return ErrInvalid
			}
			o.Ref = Ref{policy.NewID("net"), 1}
			s.Objects = append(s.Objects, o)
		}
		for i := start; i < len(s.Objects); i++ {
			if e := bindRefs(s.Objects, &s.Objects[i].Binding); e != nil {
				return e
			}
		}
		return nil
	})
}
