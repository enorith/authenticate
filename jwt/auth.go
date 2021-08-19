package jwt

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/enorith/authenticate"
	"github.com/enorith/supports/str"
)

type InvalidTokenError string

func (it InvalidTokenError) Error() string {
	return string(it)
}

var (
	DefaultAlg                = jwt.SigningMethodHS512
	DefaultExpireSecond int64 = 60 * 30
)

type User interface {
	authenticate.User
	GetJwtClaims() jwt.MapClaims
}

type Token struct {
	AccessToken string        `json:"access_token"`
	ExpireIn    int64         `json:"expire_in"`
	Type        string        `json:"type"`
	claims      jwt.MapClaims `json:"-"`
}

type TokenProvider interface {
	GetAccessToken() ([]byte, error)
}

type Guard struct {
	tokenProvider TokenProvider
	userProvider  authenticate.UserProvider
	token         Token
	user          authenticate.User
	key           []byte
	expireSecond  int64
	alg           *jwt.SigningMethodHMAC
}

func (g *Guard) Token() Token {
	return g.token
}

func (g *Guard) Key() ([]byte, error) {
	if len(g.key) < 1 {
		return nil, errors.New("jwt key not provided")
	}

	return g.key, nil
}

func (g *Guard) Alg() *jwt.SigningMethodHMAC {
	if g.alg == nil {
		return DefaultAlg
	}

	return g.alg
}

func (g *Guard) ExpireSecond() int64 {
	if g.expireSecond < 1 {
		return DefaultExpireSecond
	}

	return g.expireSecond
}

func (g *Guard) Check() (authenticate.User, error) {
	if g.user != nil {
		return g.user, nil
	}
	e := g.ParseToken()
	if e != nil {
		return nil, e
	}

	idValue := g.token.claims["sub"]
	id := authenticate.Identifier(idValue)

	g.user, e = g.userProvider.FindUserById(id)

	return g.user, e
}

func (g *Guard) User() authenticate.User {
	return g.user
}

func (g *Guard) Auth(user authenticate.User) error {
	now := time.Now().Unix()
	exp := now + g.ExpireSecond()
	claims := jwt.MapClaims{
		"iss": "",
	}
	if ju, ok := user.(User); ok {
		customClaims := ju.GetJwtClaims()
		for k, v := range customClaims {
			claims[k] = v
		}
	}
	claims["jti"] = user.UserIdentifier().Value()
	claims["sub"] = user.UserIdentifier().Value()
	claims["iat"] = now
	claims["exp"] = exp
	claims["aud"] = str.RandString(16)

	token := jwt.NewWithClaims(g.Alg(), claims)

	k, e := g.Key()
	if e != nil {
		return e
	}

	tokenString, err := token.SignedString(k)

	g.token = Token{
		AccessToken: tokenString,
		ExpireIn:    exp,
		Type:        "bearer",
		claims:      claims,
	}
	return err
}

func (g *Guard) ParseToken() error {
	ts, e := g.tokenProvider.GetAccessToken()
	if e != nil {
		return e
	}

	var token Token
	token.AccessToken = string(ts)
	t, err := jwt.ParseWithClaims(token.AccessToken, &token.claims, func(token *jwt.Token) (interface{}, error) {
		return g.Key()
	})
	if err != nil {
		return err
	}
	if !t.Valid {
		return InvalidTokenError("invalid token")
	}
	g.token = token
	return nil
}

func NewJwtGuard(tokenProvider TokenProvider, userProvider authenticate.UserProvider, key []byte) *Guard {
	return &Guard{
		tokenProvider: tokenProvider,
		userProvider:  userProvider,
		key:           key,
	}
}
