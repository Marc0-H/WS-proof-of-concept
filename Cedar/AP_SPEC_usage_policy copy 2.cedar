// Read.
permit (
    principal,
    action == Action::"Retrieve",
    resource
)
when { resource.document == "AMO" };

// Pushback
permit (
    principal,
    action == Action::"Pushback",
    resource
)
when { resource.document == "AMO" };

// Delegate/ Copy
permit (
    principal,
    action == Action::"Copy",
    resource
)
when { resource.can_copy };
