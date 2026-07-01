package pa.binding

default allow_bind := false

default binding_window_requirement_satisfied := false
default binding_pin_required := true
default binding_pin_matches := false
default binding_pin_requirement_satisfied := false
default binding_mapping_satisfied := false

# A role is allowed to create bindings to specifc other roles
allowed_bindings := {
    "HA":   {"HA", "HAP", "SEH", "SPEC", "AP"},
    "HAP":  {"HA", "HAP", "SEH", "AP"},
    "SEH":  {"SPEC", "AP"},
    "AP":   {"AP"},
    "SPEC": {"SPEC", "AP"}
}

# Check if roles of the creator of the reference and the receiver adhere to the 
# binding mapping.
binding_mapping_satisfied if {
    delegatee_role := input.delegatee.org_type
    delegatee_role in allowed_bindings[input.delegator.org_type]
}


# Check if this is a first-time access attempt and if the reference is late-bound
# If current time falls outside the binding window, return false.
binding_window_requirement_satisfied if {
    input.reference.is_bound == true
}

binding_window_requirement_satisfied if {
    input.reference.is_bound == false
    time.date(time.now_ns()) <= input.reference.bind_expiry_window
}



# Check if this is a first-time access attempt and if a binding pin is expected.
# In case the reference is already bound or no access code is expected,
# the requirement is satisfied
binding_pin_required if {
    input.reference.is_bound == false
    input.reference.expects_binding_pin == true
}

binding_pin_matches if {
    input.reference.binding_pin == input.delegatee.binding_pin
}

binding_pin_requirement_satisfied if {
    not binding_pin_required
}

binding_pin_requirement_satisfied if {
    binding_pin_required
    binding_pin_matches
}


# Check if requirements are satisfied for binding window and PIN
# Then check if the roles conform to the binding mapping.
allow_bind if {
    binding_window_requirement_satisfied
    binding_pin_requirement_satisfied
    binding_mapping_satisfied
}