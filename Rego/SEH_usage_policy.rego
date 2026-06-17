package pa.seh_usage

default allow_usage := false

# Allow SEH to read if document type is Mini-PS.
allow_usage if {
    input.action == "retrieve"
    input.reference.document == "Mini-PS"
}

# Allow SEH to pushback if document type is Mini-PS.
allow_usage if {
    input.action == "pushback"
    input.reference.document == "Mini-PS"
}

# Allow SEH to delegate if they are allowed to by the reference
allow_usage if {
    input.action == "copy"
    input.reference.can_copy == true
}

