package config

const (
	MinUserLen                     = 1
	MaxUserLen                     = 30
	MessageInvalidCredentialsError = "Credentials did not match"
	MessageMissingRequired         = "Missing required parameters."
	MessageAccountLocked           = "Unable to log in.Please contact your administrator."
	MessageTermsNotAccepted        = "terms and conditions not accepted"
	LogUserCreateSuccess           = "User created successfully: %s"
	LogUserCreateFailed            = "failed to create new user"
	LogUserUpdateSuccess           = "user updated successfully: %s"
	LogUserUpdateFailed            = "user update failed: %s"
	LogUserDeleteSuccess           = "user successfully deleted: %s"
	LogUserDeleteFailed            = "failed to delete user: %s"
	LogUserFindByEmailFailed       = "failed to find user with email: %s"
	LogUserFindByEmailSuccess      = "user found with email: %s"
	LogUserFindByIDFailed          = "failed to find user with ID: %d"
	LogUserFindByIDSuccess         = "user found with ID: %d"
	LogUserGetFromContextFailed    = "failed to get user from context"
)
