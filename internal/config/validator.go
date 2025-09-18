package config

import (
	"fmt"
	"reflect"
	"strings"
)

type Visitor interface {
	Visit(c Config)
	VisitNested(c NestedConfig)
}

type Node interface {
	Accept(v Visitor)
}

type Validator interface {
	Visitor
	Validate(any)
	Issues() []Issue
}

type Issue struct {
	Path string
	Desc string
}

type validator struct {
	path   []string
	issues []Issue
}

func (v *validator) Visit(c Config) {
	v.addIssue("nested", "oops")
	v.Validate(c)
}

func (v *validator) VisitNested(c NestedConfig) {
	v.Validate(c)
}

func (v *validator) Issues() []Issue {
	return v.issues
}

func (v *validator) addIssue(field string, format string, args ...any) {
	path := make([]string, len(v.path))
	copy(path, v.path)
	if field != "" {
		path = append(path, field)
	}
	v.issues = append(v.issues, Issue{
		Path: strings.Join(path, "."),
		Desc: fmt.Sprintf(format, args...),
	})
}

func (v *validator) enter(field string) {
	v.path = append(v.path, field)
}

func (v *validator) leave() {
	if len(v.path) > 0 {
		v.path = v.path[:len(v.path)-1]
	}
}

func (v *validator) Validate(parent any) {
	rv := reflect.ValueOf(parent)
	if rv.Kind() == reflect.Pointer {
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return
	}
	rt := rv.Type()
	for i := 0; i < rv.NumField(); i++ {
		fv := rv.Field(i)
		ft := rt.Field(i)
		if !fv.CanInterface() {
			continue
		}
		child, ok := fv.Interface().(Node)
		if !ok {
			if fv.CanAddr() {
				child, ok = fv.Addr().Interface().(Node)
			}
		}
		if !ok {
			continue
		}
		name := ft.Tag.Get("yaml")
		if name == "" {
			name = strings.ToLower(ft.Name)
		} else if i := strings.Index(name, ","); i >= 0 {
			name = name[:i]
		}
		v.enter(name)
		child.Accept(v)
		v.leave()
	}
}
