package pa.access

default allow_access := false

allow_access if {
    input.caller.user_id == input.reference.bound_user_id
    input.reference.revoked == false
    input.reference.expiry > time.date()
}