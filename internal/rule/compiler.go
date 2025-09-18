package rule

import (
	"errors"
	"reflect"

	"github.com/expr-lang/expr"
)

type Mode string

const (
	ModeAllow Mode = "allow"
	ModeDeny  Mode = "deny"
)

type options struct {
	when  []expr.Option
	user  []expr.Option
	roles []expr.Option
}

type Builder struct {
	opts *options
	rule *rule
}

func (b *Builder) When(input string) error {
	if input == "" {
		return errors.New("required for all rules")
	}
	when, err := expr.Compile(input, b.opts.when...)
	if err != nil {
		return err
	}
	b.rule.when = when
	return nil
}

func (b *Builder) User(input string) error {
	if b.rule.deny {
		return errors.New("forbidden for deny rule")
	}
	if input == "" {
		return errors.New("required for allow rule")
	}
	user, err := expr.Compile(input, b.opts.user...)
	if err != nil {
		return err
	}
	b.rule.user = user
	return nil
}

func (b *Builder) Roles(input string) error {
	if input == "" {
		return nil
	}
	if b.rule.deny {
		return errors.New("forbidden for deny rule")
	}
	roles, err := expr.Compile(input, b.opts.roles...)
	if err != nil {
		return err
	}
	b.rule.roles = roles
	return nil
}

func (b *Builder) Build() Rule {
	if b.rule.when == nil {
		panic("when is required")
	}
	if b.rule.user == nil && !b.rule.deny {
		panic("user is required for allow rule")
	}
	return b.rule
}

type Compiler struct {
	opts *options
}

func NewCompiler() *Compiler {
	base := []expr.Option{
		expr.Env(Environment{}),
		expr.Optimize(true),
	}
	hint := func(k reflect.Kind) []expr.Option {
		opts := make([]expr.Option, 0, len(base)+1)
		copy(opts, base)
		return append(opts, expr.AsKind(k))
	}
	return &Compiler{
		opts: &options{
			when:  hint(reflect.Bool),
			user:  hint(reflect.String),
			roles: hint(reflect.Slice),
		},
	}
}

func (c *Compiler) Builder(mode Mode) *Builder {
	return &Builder{
		opts: c.opts,
		rule: &rule{deny: mode != ModeAllow},
	}
}
