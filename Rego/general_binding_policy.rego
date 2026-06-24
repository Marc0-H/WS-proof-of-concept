package pa.binding

default allow_bind := false

default binding_window_requirement_satisfied := false
default binding_pin_required := true
default binding_pin_matches := false
default binding_pin_requirement_satisfied := false


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


# HA can delegate to anyone
allow_bind if {
    binding_window_requirement_satisfied
    binding_pin_requirement_satisfied

    input.delegator.org_type == "HA"
}

# HAP can delegate to anyone except Specialists
allow_bind if {
    binding_window_requirement_satisfied
    binding_pin_requirement_satisfied

    input.delegator.org_type == "HAP"
    input.delegatee.org_type != "SPEC"
}

# SEH can delegate to specialist or pharmacy
allow_bind if {
    binding_window_requirement_satisfied
    binding_pin_requirement_satisfied

    input.delegator.org_type == "SEH"
    input.delegatee.org_type in ["SPEC", "AP"]
}

# Pharmacy can only delegate to Pharmacy.
allow_bind if {
    binding_window_requirement_satisfied
    binding_pin_requirement_satisfied

    input.delegator.org_type == "AP"
    input.delegatee.org_type == "AP"
}

# Specialist can delegate to specialist.
allow_bind if {
    binding_window_requirement_satisfied
    binding_pin_requirement_satisfied

    input.delegator.org_type == "SPEC"
    input.delegatee.org_type in ["SPEC", "AP"]
}