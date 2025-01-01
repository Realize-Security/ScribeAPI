package config

const (
	ExitSuccess     = 0  // Successful execution
	ExitError       = 1  // General error
	ExitUsageError  = 2  // Command line usage error
	ExitDataError   = 65 // Data format error
	ExitNoInput     = 66 // Cannot open input
	ExitNoUser      = 67 // User does not exist
	ExitNoHost      = 68 // Host does not exist
	ExitUnavailable = 69 // Service unavailable
	ExitSoftware    = 70 // Internal software error
	ExitOSError     = 71 // System error (e.g., cannot create pipe)
	ExitOSFile      = 72 // Critical OS file missing
	ExitCantCreate  = 73 // Cannot create output file
	ExitIOError     = 74 // Input/output error
	ExitTempFail    = 75 // Temporary failure; user is invited to retry
	ExitProtocol    = 76 // Remote error in protocol
	ExitNoPerm      = 77 // Permission denied
	ExitConfig      = 78 // Configuration error

	ExitNotFound        = 40 // Resource not found
	ExitAlreadyExists   = 41 // Resource already exists
	ExitTimedOut        = 42 // Operation timed out
	ExitNotImplemented  = 43 // Feature not implemented
	ExitInvalidArgument = 44 // Invalid argument provided
	ExitBadConnection   = 45 // Database/Network connection issue
)
