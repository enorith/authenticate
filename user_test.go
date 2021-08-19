package authenticate_test

import (
	"github.com/enorith/authenticate"
	"testing"
)

func TestUserIdentifier(t *testing.T) {
	id := authenticate.Identifier(42)
	t.Log("test result int", id.Int64())
	t.Log("test result string", id.String())


	id2 := authenticate.Identifier("42")
	t.Log("test2 result string", id2.String())
	t.Log("test2 result int", id2.Int64())
}