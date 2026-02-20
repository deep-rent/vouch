package couch

const (
	// CouchDBUserNameHeader is the header used to proxy the username to CouchDB.
	CouchDBUserNameHeader = "X-Auth-CouchDB-UserName"
	// CouchDBRolesHeader is the header used to proxy the roles to CouchDB.
	CouchDBRolesHeader = "X-Auth-CouchDB-Roles"
	// CouchDBTokenHeader is the header used for the proxy's shared secret with CouchDB.
	CouchDBTokenHeader = "X-Auth-CouchDB-Token"
)
