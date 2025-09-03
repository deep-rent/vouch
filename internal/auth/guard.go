package auth

import (
	"errors"
	"net/http"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/rules"
	"github.com/deep-rent/vouch/internal/token"
)

type Scope struct {
	User string
	Role string
}

var ErrForbidden = errors.New("insufficient permissions")

type Guard struct {
	parser *token.Parser
	engine *rules.Engine
}

func NewGuard(cfg config.Config) (*Guard, error) {
	parser, err := token.NewParser(cfg.Token)
	if err != nil {
		return nil, err
	}
	engine, err := rules.NewEngine(cfg.Rules)
	if err != nil {
		return nil, err
	}
	return &Guard{
		parser: parser,
		engine: engine,
	}, nil
}

func (g *Guard) Check(req *http.Request) (scope Scope, err error) {
	tok, err := g.parser.Parse(req)
	if err != nil {
		return
	}
	env := rules.NewEnvironment(tok, req)
	res, err := g.engine.Eval(env)
	if err != nil {
		return
	}
	if !res.Pass {
		err = ErrForbidden
		return
	}
	scope = Scope{
		User: res.User,
		Role: res.Role,
	}
	return
}
