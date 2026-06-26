forbid (principal, action, resource)
when { !resource.is_bound };

forbid (principal, action, resource)
when { principal.user_uzi_id != resource.bound_user_uzi_id };

forbid (principal, action, resource)
when { resource.revoked };

forbid (principal, action, resource)
when { datetime(context.current_time) > datetime(resource.expiry) };

//
// IF PHARMACIST
//
// Allow pharmacist to read if document type is AMO.
permit (
    principal,
    action == Action::"Retrieve",
    resource
)
when
{
    principal.org_type == "AP" &&
    resource.document == "AMO" &&
    resource.allowed_permissions.contains("Retrieve")
};

// Allow pharmacist to pushback if document type is AMO.
permit (
    principal,
    action == Action::"Pushback",
    resource
)
when
{
    principal.org_type == "AP" &&
    resource.document == "AMO" &&
    resource.allowed_permissions.contains("Pushback")
};

// Allow pharmacist to delegate if they are allowed to by the reference.
permit (
    principal,
    action == Action::"Copy",
    resource
)
when { principal.org_type == "AP" && resource.can_copy };

//
// IF SPECIALIST
//
// Allow specialist to read if document type is AMO.
permit (
    principal,
    action == Action::"Retrieve",
    resource
)
when
{
    principal.org_type == "SPEC" &&
    resource.document == "AMO" &&
    resource.allowed_permissions.contains("Retrieve")
};

// Allow specialist to pushback if document type is AMO.
permit (
    principal,
    action == Action::"Pushback",
    resource
)
when
{
    principal.org_type == "SPEC" &&
    resource.document == "AMO" &&
    resource.allowed_permissions.contains("Pushback")
};

// Allow specialist to delegate if they are allowed to by the reference.
permit (
    principal,
    action == Action::"Copy",
    resource
)
when { principal.org_type == "SPEC" && resource.can_copy };

//
// IF 'HUISARTS'
//
// Allow HA to read if document type is AMO, NHG-PS, Mini-PS.
permit (
    principal,
    action == Action::"Retrieve",
    resource
)
when
{
    principal.org_type == "HA" &&
    ["NHG-PS", "Mini-PS", "AMO"].contains(resource.document) &&
    resource.allowed_permissions.contains("Retrieve")
};

// Allow HA to pushback if document type is AMO, NHG-PS, Mini-PS.
permit (
    principal,
    action == Action::"Pushback",
    resource
)
when
{
    principal.org_type == "HA" &&
    ["NHG-PS", "Mini-PS", "AMO"].contains(resource.document) &&
    resource.allowed_permissions.contains("Pushback")
};

// Allow HA to delegate if they are allowed to by the reference.
permit (
    principal,
    action == Action::"Copy",
    resource
)
when { principal.org_type == "HA" && resource.can_copy };

//
// IF 'HUISARTSENPOST'
//
// Allow HAP to read if document type is AMO, NHG-PS, Mini-PS.
permit (
    principal,
    action == Action::"Retrieve",
    resource
)
when
{
    principal.org_type == "HAP" &&
    ["NHG-PS", "Mini-PS", "AMO"].contains(resource.document) &&
    resource.allowed_permissions.contains("Retrieve")
};

// Allow HAP to pushback if document type is AMO, NHG-PS, Mini-PS.
permit (
    principal,
    action == Action::"Pushback",
    resource
)
when
{
    principal.org_type == "HAP" &&
    ["NHG-PS", "Mini-PS", "AMO"].contains(resource.document) &&
    resource.allowed_permissions.contains("Pushback")
};

// Allow HA to delegate if they are allowed to by the reference.
permit (
    principal,
    action == Action::"Copy",
    resource
)
when { principal.org_type == "HAP" && resource.can_copy };

//
// IF 'SPOED EISENDE HULP'
//
// Allow SEH to read if document type is AMO, Mini-PS.
permit (
    principal,
    action == Action::"Retrieve",
    resource
)
when
{
    principal.org_type == "SEH" &&
    ["Mini-PS", "AMO"].contains(resource.document) &&
    resource.allowed_permissions.contains("Retrieve")
};

// Allow SEH to pushback if document type is AMO, Mini-PS.
permit (
    principal,
    action == Action::"Pushback",
    resource
)
when
{
    principal.org_type == "SEH" &&
    ["Mini-PS", "AMO"].contains(resource.document) &&
    resource.allowed_permissions.contains("Pushback")
};

// Allow SEH to delegate if they are allowed to by the reference.
permit (
    principal,
    action == Action::"Copy",
    resource
)
when { principal.org_type == "SEH" && resource.can_copy };
