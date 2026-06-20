package pa.ap_usage

default allow_usage := false

# Allow pharmacist / specialist to read if document type is AMO.
allow_usage if {
    input.action == "retrieve"
    input.action in input.reference.allowed_permissions
    input.reference.document == "AMO"
}

# Allow pharmacist / specialist to pushback
allow_usage if {
    input.action == "pushback"
    input.action in input.reference.allowed_permissions
    input.reference.document == "AMO"
}

# Allow pharmacist / specialist to delegate if they are allowed to by the reference
allow_usage if {
    input.action == "copy"
    input.reference.can_copy == true
}

