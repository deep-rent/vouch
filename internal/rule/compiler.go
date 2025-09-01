package rule

import (
	"fmt"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// Mode defines the behavior of a rule when matched.
const (
	// ModeAllow grants access, authenticating the request on behalf of the
	// specified user.
	ModeAllow = "allow"
	// ModeDeny implies that access should be denied, preventing the
	// request from proceeding.
	ModeDeny = "deny"
)

// Config represents a single, uncompiled authorization rule.
// It is intended to be unmarshaled from a configuration source, such as YAML.
// The expressions in When, User, and Role are plain strings that must be
// compiled before evaluation.
type Config struct {
	// Mode indicates whether the rule allows or denies access when matched.
	// Supported values are "allow" and "deny".
	Mode string `yaml:"mode"`

	// When specifies the condition under which the rule applies.
	// This expression is mandatory for every rule and must evaluate to a
	// boolean.
	When string `yaml:"when"`

	// User is an optional expression that determines the CouchDB user to
	// authenticate as. This field is only used in "allow" mode. If specified,
	// the expression must return a string. An empty or missing result will
	// cause the request to be forwarded anonymously. Must be left undefined in
	// "deny" mode.
	User string `yaml:"user,omitempty"`

	// Role is an optional expression that specifies CouchDB roles for
	// authentication. This field is only used in "allow" mode. The expression
	// must return a string, a comma-separated list of strings, or an array of
	// strings. Must be left undefined in "deny" mode.
	Role string `yaml:"role,omitempty"`
}

// Rule represents a rule configuration whose expressions have been
// compiled into executable programs.
type Rule struct {
	deny bool
	when *vm.Program // required; evaluates to bool
	user *vm.Program // optional; evaluates to string
	role *vm.Program // optional; evaluates to string or []string
}

// evalWhen checks if the rule's condition is met.
func (r *Rule) evalWhen(env Environment) (pass bool, err error) {
	v, err := expr.Run(r.when, env)
	if err != nil {
		err = fmt.Errorf("eval when: %w", err)
		return
	}
	b, ok := v.(bool)
	if !ok {
		err = fmt.Errorf("when must evaluate to bool, got %T", v)
		return
	}
	pass = b
	return
}

// evalUser returns the CouchDB user to authenticate as, or an empty string
// to forward the request anonymously.
func (r *Rule) evalUser(env Environment) (user string, err error) {
	if r.user == nil {
		return
	}
	v, err := expr.Run(r.user, env)
	if err != nil {
		err = fmt.Errorf("eval user: %w", err)
		return
	}
	s, ok := v.(string)
	if !ok {
		err = fmt.Errorf("user must evaluate to string, got %T", v)
		return
	}
	user = s
	return
}

// evalRole returns the CouchDB role(s) for authentication as a comma-joined
// string, or an empty string if no roles must be assigned.
func (r *Rule) evalRole(env Environment) (role string, err error) {
	if r.role == nil {
		return
	}
	v, err := expr.Run(r.role, env)
	if err != nil {
		err = fmt.Errorf("eval role: %w", err)
		return
	}
	switch t := v.(type) {
	case string:
		role = t
		return
	case []string:
		role = strings.Join(t, ",")
		return
	case []any:
		a := make([]string, len(t))
		for i, e := range t {
			s, ok := e.(string)
			if !ok {
				return "", fmt.Errorf("role at %d must be string, was %T", i, e)
			}
			a[i] = s
		}
		role = strings.Join(a, ",")
		return
	default:
		err = fmt.Errorf("role must evaluate to string or []string, got %T", v)
		return
	}
}

// Eval executes the compiled expressions of this rule against the given
// environment.
func (r *Rule) Eval(env Environment) (
	skip bool, // whether this rule should be applied or skipped
	deny bool, // whether this rule grants or denies access (if not skipped)
	user string, // the CouchDB user to authenticate as (if not denied)
	role string, // the CouchDB role(s) to authenticate with (if not denied)
	err error, // any error that occurred during evaluation
) {
	pass, err := r.evalWhen(env)
	if err != nil {
		return
	}
	if !pass {
		skip = true
		return
	}
	if r.deny {
		deny = true
		return
	}
	user, err = r.evalUser(env)
	if err != nil {
		return
	}
	role, err = r.evalRole(env)
	if err != nil {
		user = ""
		return
	}
	return
}

// Compiler encapsulates rule compilation details.
type Compiler struct {
	opts []expr.Option
}

// NewCompiler creates a new rule compiler.
func NewCompiler() *Compiler {
	return &Compiler{opts: []expr.Option{expr.Env(Environment{})}}
}

// Compile compiles the rule definitions into a set of executable programs.
func (c *Compiler) Compile(rules []Config) ([]Rule, error) {
	out := make([]Rule, 0, len(rules))
	for i, r := range rules {
		rule, err := c.compile(i, r)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, nil
}

// compile compiles a single authorization rule.
func (c *Compiler) compile(i int, rule Config) (Rule, error) {
	mode := strings.ToLower(strings.TrimSpace(rule.Mode))
	if mode != ModeAllow && mode != ModeDeny {
		return Rule{}, fmt.Errorf(
			"rules[%d].mode must be '%s' or '%s'",
			i, ModeAllow, ModeDeny,
		)
	}

	w := strings.TrimSpace(rule.When)
	if w == "" {
		return Rule{}, fmt.Errorf(
			"rules[%d].when is required", i,
		)
	}
	when, err := expr.Compile(w, c.opts...)
	if err != nil {
		return Rule{}, fmt.Errorf(
			"compile rules[%d].when: %w", i, err,
		)
	}

	var user, role *vm.Program
	if mode == ModeDeny {
		if strings.TrimSpace(rule.User) != "" {
			return Rule{}, fmt.Errorf(
				"rules[%d]: user must not be set for %s mode",
				i, ModeDeny,
			)
		}
		if strings.TrimSpace(rule.Role) != "" {
			return Rule{}, fmt.Errorf(
				"rules[%d]: role must not be set for %s mode",
				i, ModeDeny,
			)
		}
	} else {
		u := strings.TrimSpace(rule.User)
		if u != "" {
			user, err = expr.Compile(u, c.opts...)
			if err != nil {
				return Rule{}, fmt.Errorf(
					"compile rules[%d].user: %w", i, err,
				)
			}
		}
		r := strings.TrimSpace(rule.Role)
		if r != "" {
			role, err = expr.Compile(r, c.opts...)
			if err != nil {
				return Rule{}, fmt.Errorf(
					"compile rules[%d].role: %w", i, err,
				)
			}
		}
	}

	return Rule{
		deny: mode == ModeDeny,
		when: when,
		user: user,
		role: role,
	}, nil
}
