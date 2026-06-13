package pa.usage

default allow_usage := false

# Allow pharmacist / specialist to read if document type is AMO.
allow_usage if {
    input.action == "retrieve"
    input.reference.document == "AMO"
}

# Allow pharmacist / specialist to pushback if ... (to be continued)
allow_usage if {
    input.action == "pushback"
    input.reference.document == "AMO"
}

# Allow pharmacist / specialist to delegate if they are allowed to by the reference
allow_usage if {
    input.action == "copy"
    input.reference.can_copy == true
}

