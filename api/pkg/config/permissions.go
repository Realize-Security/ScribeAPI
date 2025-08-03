package config

// Logging
const (
	LogFailedToRetrievePermissions = "failed to retrieve permissions"
	LonUnableToCachePermissions    = "unable to cache permissions %v"
	LogUserUnauthorised            = "user %d unauthorised. missing permission %s"
)

// Permissions
const (
	// ProjectCreate allows permission to create a new project
	ProjectCreate = "create_project"
	// ProjectList allows permission to list existing projects
	ProjectList = "list_projects"
	// ProjectRead allows permission to view projects
	ProjectRead = "read_project"
	// ProjectUpdate allows permission to update projects
	ProjectUpdate = "update_project"
	// ProjectDelete allows permission to delete projects
	ProjectDelete = "delete_project"
)

// Users
const (
	// UserCreate allows permission to create a new user
	UserCreate = "create_user"
	// UserList allows permission to list existing users
	UserList = "list_users"
	// UserRead allows permission to view users
	UserRead = "read_user"
	// UserUpdate allows permission to update users
	UserUpdate = "update_user"
	// UserDelete allows permission to delete users
	UserDelete = "delete_user"
	// UserToggleEnabled allows permission to disable and enable user accounts
	UserToggleEnabled = "toggle_enabled_user"
)
