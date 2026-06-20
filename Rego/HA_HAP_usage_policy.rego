package pa.ha_usage

default allow_usage := false

# Allow HA/HAP to read if document type is NHG PS.
allow_usage if {
    input.action == "Retrieve"
    input.action in input.reference.allowed_permissions
    input.reference.document in ["NHG-PS", "Mini-PS", "AMO"]
}

# Allow HA/HAP to pushback if document type is NHG PS.
allow_usage if {
    input.action == "Pushback"
    input.action in input.reference.allowed_permissions
    input.reference.document in ["NHG-PS", "Mini-PS", "AMO"]
}

# Allow HA/HAP to delegate if they are allowed to by the reference
allow_usage if {
    input.action == "Copy"
    input.reference.can_copy == true
}

