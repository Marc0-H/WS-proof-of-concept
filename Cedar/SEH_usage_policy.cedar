// Read.
permit (
    principal,
    action == Action::"Retrieve",
    resource
)
when { resource.document == "Mini-PS" };

// Pushback
permit (
    principal,
    action == Action::"Pushback",
    resource
)
when { resource.document == "Mini-PS" };

// Delegate/ Copy
permit (
    principal,
    action == Action::"Copy",
    resource
)
when { resource.can_copy };
