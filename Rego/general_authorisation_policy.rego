package pa.access

default allow_access := false

allow_access if {
    input.reference.is_bound == true
    input.delegatee.user_id == input.reference.bound_user_id
    input.reference.revoked == false
    input.reference.expiry > time.date(time.now_ns())
}