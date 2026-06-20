package pa.seh_usage

default allow_usage := false

# Allow SEH to read if document type is Mini-PS.
allow_usage if {
    input.action == "retrieve"
    input.action in input.reference.allowed_permissions
    input.reference.document in ["Mini-PS", "AMO"]
}

# Allow SEH to pushback if document type is Mini-PS.
allow_usage if {
    input.action == "pushback"
    input.action in input.reference.allowed_permissions
    input.reference.document in ["Mini-PS", "AMO"]
}

# Allow SEH to delegate if they are allowed to by the reference
allow_usage if {
    input.action == "copy"
    input.reference.can_copy == true
}

