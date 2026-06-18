package pa.ha_usage

default allow_usage := false

# Allow HA/HAP to read if document type is NHG PS.
allow_usage if {
    input.action == "retrieve"
    input.reference.document == "NHG-PS"
}

# Allow HA/HAP to pushback if document type is NHG PS.
allow_usage if {
    input.action == "pushback"
    input.reference.document == "NHG-PS"
}

# Allow HA/HAP to delegate if they are allowed to by the reference
allow_usage if {
    input.action == "copy"
    input.reference.can_copy == true
}

