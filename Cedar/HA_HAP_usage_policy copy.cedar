// Read.
permit (
    principal,
    action == Action::"Retrieve",
    resource
)
when { resource.document == "NHG-PS" };

// Pushback
permit (
    principal,
    action == Action::"Pushback",
    resource
)
when { resource.document == "NHG-PS" };

// Delegate/ Copy
permit (
    principal,
    action == Action::"Copy",
    resource
)
when { resource.can_copy };
