// Global deny when late-bind window expired
forbid (
    principal,
    action == Action::"bind",
    resource
)
when
{
    !resource.is_bound &&
    datetime(context.current_time) > datetime(resource.bind_expiry_window)
};

// Global Deny when binding pin required but invalid
forbid (
    principal,
    action == Action::"bind",
    resource
)
when
{
    !resource.is_bound &&
    resource.expects_binding_pin &&
    principal.binding_pin != resource.binding_pin
};

// HA can delegate to anyone
permit (
    principal,
    action == Action::"bind",
    resource
)
when { principal.org_type == "HA" };

//HAP cannot delegate to Specialists
permit (
    principal,
    action == Action::"bind",
    resource
)
when
{ principal.org_type == "HAP" && context.delegatee_org_type != "Specialist" };

// SEH can delegate to Specialist and pharmacist
permit (
    principal,
    action == Action::"bind",
    resource
)
when
{ principal.org_type == "SEH" && context.delegatee_org_type == "Specialist" };

permit (
    principal,
    action == Action::"bind",
    resource
)
when { principal.org_type == "SEH" && context.delegatee_org_type == "AP" };

// Pharmacy can only delegate to Pharmacy
permit (
    principal,
    action == Action::"bind",
    resource
)
when { principal.org_type == "AP" && context.delegatee_org_type == "AP" };

// Specialist can delegate to Specialist and pharmacy
permit (
    principal,
    action == Action::"bind",
    resource
)
when
{
    principal.org_type == "Specialist" &&
    context.delegatee_org_type == "Specialist"
};

permit (
    principal,
    action == Action::"bind",
    resource
)
when
{ principal.org_type == "Specialist" && context.delegatee_org_type == "AP" };
