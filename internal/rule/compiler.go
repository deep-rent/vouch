package rule

import (
	"errors"
	"reflect"

	"github.com/expr-lang/expr"
)

// Mode specifies whether a rule allows or denies access.
type Mode string

const (
	// ModeAllow indicates that the rule allows access when matched.
	ModeAllow Mode = "allow"
	// ModeDeny indicates that the rule denies access when matched.
	ModeDeny Mode = "deny"
)

// options holds compilation options tailored to the different rule expressions.
type options struct {
	when  []expr.Option
	user  []expr.Option
	roles []expr.Option
}

// Builder helps compile a Rule step-by-step.
// It is not safe for concurrent use.
type Builder struct {
	opts *options
	rule *rule
}

// When compiles and sets the when expression of the rule.
// This expression is required for all rules.
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

// User compiles and sets the user expression of the rule.
// This expression is required for allow rules and forbidden for deny rules.
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

// Roles compiles and sets the roles expression of the rule.
// This expression is optional for allow rules and forbidden for deny rules.
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

// Build finalizes and returns the compiled Rule.
// It panics if the rule is incomplete.
func (b *Builder) Build() Rule {
	if b.rule.when == nil {
		panic("when is required")
	}
	if b.rule.user == nil && !b.rule.deny {
		panic("user is required for allow rule")
	}
	return b.rule
}

// Compiler compiles rules from their string representations.
type Compiler struct {
	opts *options
}

// NewCompiler initializes a new compiler.
func NewCompiler() *Compiler {
	base := []expr.Option{
		expr.Env(Environment{}),
		expr.Optimize(true),
	}
	// Tell the compiler what type we expect for each expression to enable
	// further optimizations
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

// Builder creates a new Builder for the given rule mode.
func (c *Compiler) Builder(mode Mode) *Builder {
	return &Builder{
		opts: c.opts,
		rule: &rule{deny: mode != ModeAllow},
	}
}
