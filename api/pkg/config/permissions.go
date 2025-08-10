package config

// Logging
const (
	LogFailedToRetrievePermissions = "failed to retrieve permissions"
	LogUnableToCachePermissions    = "unable to cache permissions %v"
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

// Organisations
const (
	// OrganisationCreate allows permission to create a new organisation
	OrganisationCreate = "create_organisation"
	// OrganisationList allows permission to list existing organisations
	OrganisationList = "list_organisation"
	// OrganisationRead allows permission to view organisations
	OrganisationRead = "read_organisation"
	// OrganisationUpdate allows permission to update organisations
	OrganisationUpdate = "update_organisation"
	// OrganisationDelete allows permission to delete organisations
	OrganisationDelete = "delete_organisation"
)
