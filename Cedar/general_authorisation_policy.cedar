permit (principal, action, resource)
when
{
    context.delegatee_user_uzi_id == resource.bound_user_uzi_id &&
    !resource.revoked &&
    datetime(context.current_time) < datetime(resource.expiry)
};
