// Read.
permit (
    principal,
    action == Action::"Retrieve",
    resource
)
when
{
    ["AMO"].contains(resource.document) &&
    resource.allowed_permissions.contains("Retrieve")
};

// Pushback
permit (
    principal,
    action == Action::"Pushback",
    resource
)
when
{
    ["AMO"].contains(resource.document) &&
    resource.allowed_permissions.contains("Pushback")
};

// Delegate/ Copy
permit (
    principal,
    action == Action::"Copy",
    resource
)
when
{
    ["AMO"].contains(resource.document) &&
    resource.allowed_permissions.contains(action)
};
