package rule

import (
	"net/http"

	"github.com/deep-rent/vouch/internal/auth"
	"github.com/deep-rent/vouch/internal/token"
)

type bouncer struct {
	parser token.Parser
	engine Engine
}

func NewBouncer(parser token.Parser, engine Engine) auth.Bouncer {
	return &bouncer{
		parser: parser,
		engine: engine,
	}
}

func (b *bouncer) Check(req *http.Request) (auth.Access, *auth.AccessError) {
	claims, err := b.parser.Parse(req)
	if err != nil {
		return auth.Access{}, &auth.AccessError{
			Cause:      err,
			StatusCode: http.StatusUnauthorized,
		}
	}
	env := NewEnvironment(claims, req.Method, req.URL.Path)
	access, err := b.engine.Eval(env)
	if err != nil {
		return auth.Access{}, &auth.AccessError{
			Cause:      err,
			StatusCode: http.StatusForbidden,
		}
	}
	return access, nil
}
