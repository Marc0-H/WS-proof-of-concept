permit (principal, action, resource)
when
{
    context.delegatee_id == resource.bound_user_id &&
    !resource.revoked &&
    datetime(context.current_time) < datetime(resource.expiry)
};
