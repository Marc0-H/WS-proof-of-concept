package pa.binding

default allow_bind := false

# This says: (binding window is valid if reference is
# already bound) or (if reference is not bound and current time 
# does not surpass first bind expiry window).
# 
# binding_window_valid will thus always be true if reference
# is already bound
binding_window_valid if {
    input.reference.is_bound
}

binding_window_valid if {
    not input.reference.is_bound
    time.date() <= input.reference.bind_expiry_window
}




# HA can delegate to anyone
allow_bind if {
    binding_window_valid

    input.delegator_type == "HA"
}

# HAP can delegate to anyone except Specialists
allow_bind if {
    binding_window_valid

    input.delegator_type == "HAP"
    input.target.org_type != "Specialist"
}

# SEH can delegate to specialist or pharmacy
allow_bind if {
    binding_window_valid

    input.delegator_type == "SEH"
    input.target.org_type == "Specialist"
}
allow_bind if {
    input.delegator_type == "SEH"
    input.target.org_type == "AP"
}

# Pharmacy can only delegate to Pharmacy.
allow_bind if {
    binding_window_valid

    input.delegator_type == "AP"
    input.target.org_type == "AP"
}

# Specialist can delegate to specialist.
allow_bind if {
    binding_window_valid

    input.delegator_type == "Specialist"
    input.target.org_type == "Specialist"
}

# Specialist can delegate to pharmacy.
allow_bind if {
    binding_window_valid

    input.delegator_type == "Specialist"
    input.target.org_type == "AP"
}