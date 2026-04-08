package hooks

// Event name constants. All event names follow the "noun.verb" pattern.
const (
	EventUserCreated      = "user.created"
	EventUserLogin        = "user.login"
	EventUserDeleted      = "user.deleted"
	EventUserInvited      = "user.invited"
	EventUserRoleAssigned = "user.role.assigned"
	EventUserRoleRevoked  = "user.role.revoked"
	EventUserTOSAccepted  = "user.tos.accepted"
	EventCredentialAdded  = "user.credential.added"
)
