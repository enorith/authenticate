package authenticate

type Guard interface {
	Check() (User, error)
	User() User
	Auth(User) error
}
