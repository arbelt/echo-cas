package echo_cas

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"gopkg.in/cas.v2"
)

type CasMw struct {
	client *cas.Client
}

func New(options *cas.Options) *CasMw {
	mw := new(CasMw)
	mw.client = cas.NewClient(options)
	return mw
}

func (mw *CasMw) CasClient() *cas.Client {
	return mw.client
}

func (mw *CasMw) SetHeaders(next echo.HandlerFunc) echo.HandlerFunc {
	return func(ctx echo.Context) error {
		r := ctx.Request()
		username := cas.Username(r)
		attrs := cas.Attributes(r)
		r.Header.Set("X-CAS-User", username)
		for k := range attrs {
			r.Header.Set(fmt.Sprintf("X-CAS-Attr-%s", k), attrs.Get(k))
		}
		ctx.SetRequest(r)
		return next(ctx)
	}
}

// Remove ticket from URL params (this gets set in a cookie during the CAS auth flow)
func (mw *CasMw) RemoveParam(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		r := c.Request()
		params := c.QueryParams()
		if params.Get("ticket") == "" {
			return next(c)
		}
		params.Del("ticket")
		query := params.Encode()
		newUrl := r.URL
		newUrl.RawQuery = query
		return c.Redirect(http.StatusFound, newUrl.String())
	}
}

// Largely for local development, but set the X-Forwarded-Proto header to https so that the callback from HarvardKey
// has the right URL.
func (mw *CasMw) ForceHTTPS(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		r := c.Request()
		r.Header.Set("X-Forwarded-Proto", "https")
		c.SetRequest(r)
		return next(c)
	}
}

// Wrap the 2 middlewares from cas package. This needs to be used first.
func (mw *CasMw) Auth(next echo.HandlerFunc) echo.HandlerFunc {
	authHandler := echo.WrapMiddleware(mw.client.Handle)
	checkHandler := echo.WrapMiddleware(mw.client.Handler)
	return authHandler(checkHandler(next))
}

func (mw *CasMw) AuthnOnly(next echo.HandlerFunc) echo.HandlerFunc {
	handler := echo.WrapMiddleware(mw.client.Handle)
	return handler(next)
}

func (mw *CasMw) RequireCas(next echo.HandlerFunc) echo.HandlerFunc {
	handler := echo.WrapMiddleware(mw.client.Handler)
	return handler(next)
}

// All of the middlewares bundled together.
func (mw *CasMw) All(next echo.HandlerFunc) echo.HandlerFunc {
	return mw.ForceHTTPS(mw.Auth(mw.RemoveParam(mw.SetHeaders(next))))
}
