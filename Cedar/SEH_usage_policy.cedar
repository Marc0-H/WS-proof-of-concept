// Read.
permit (
    principal,
    action == Action::"Retrieve",
    resource
)
when
{
    ["Mini-PS", "AMO"].contains(resource.document) &&
    resource.allowed_permissions.contains(action)
};

// Pushback
permit (
    principal,
    action == Action::"Pushback",
    resource
)
when
{
    ["Mini-PS", "AMO"].contains(resource.document) &&
    resource.allowed_permissions.contains(action)
};

// Delegate/ Copy
permit (
    principal,
    action == Action::"Copy",
    resource
)
when { resource.can_copy };
