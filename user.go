package authenticate

import "strconv"

type UserIdentifier struct {
	v interface{}
}

func (id UserIdentifier) Int64() int64 {
	if i, ok := id.v.(int); ok {
		return int64(i)
	}
	if i, ok := id.v.(int32); ok {
		return int64(i)
	}
	if i, ok := id.v.(int64); ok {
		return i
	}
	if i, ok := id.v.(float64); ok {
		return int64(i)
	}

	if i, ok := id.v.(string); ok {
		parseInt, _ := strconv.ParseInt(i, 10, 64)
		return parseInt
	}
	return 0
}

func (id UserIdentifier) String() string {
	switch id.v.(type) {
	case int:
		strconv.FormatInt(id.Int64(), 10)
	case int32:
		strconv.FormatInt(id.Int64(), 10)
	case int64:
		strconv.FormatInt(id.Int64(), 10)
	}

	if i, ok := id.v.(string); ok {
		return i
	}

	return ""
}

func (id UserIdentifier) Value() interface{} {
	return id.v
}

type User interface {
	UserIdentifier() UserIdentifier
}

type UserProvider interface {
	FindUserById(UserIdentifier) (User, error)
}

func Identifier(v interface{}) UserIdentifier {
	return UserIdentifier{v}
}

type Credential interface {
}
