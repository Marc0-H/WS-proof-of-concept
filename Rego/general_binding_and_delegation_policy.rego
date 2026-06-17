package pa.binding

default allow_bind := false

# Check if this is a first-time access attempt and if the reference is late-bound
# If current time falls outside the binding window, return false.
binding_window_valid if {
    input.reference.is_bound == true
}

binding_window_valid if {
    input.reference.is_bound == false
    time.date(time.now_ns()) <= input.reference.bind_expiry_window
}




# Check if this is a first-time access attempt and if a binding pin is expected.
# In case the reference is already bound or no access code is expected, return true.
validate_patient_binding_pin if {
    input.reference.is_bound == true
}

validate_patient_binding_pin if {
    input.reference.is_bound == false
    input.reference.expects_binding_pin == false
}

validate_patient_binding_pin if {
    input.reference.is_bound == false
    input.reference.expects_binding_pin == true
    input.reference.binding_pin == input.delegatee.binding_pin
}



# HA can delegate to anyone
allow_bind if {
    binding_window_valid
    validate_patient_binding_pin

    input.delegator.org_type == "HA"
}

# HAP can delegate to anyone except Specialists
allow_bind if {
    binding_window_valid
    validate_patient_binding_pin

    input.delegator.org_type == "HAP"
    input.delegatee.org_type != "Specialist"
}

# SEH can delegate to specialist or pharmacy
allow_bind if {
    binding_window_valid
    validate_patient_binding_pin

    input.delegator.org_type == "SEH"
    input.delegatee.org_type == "Specialist"
}
allow_bind if {
    input.delegator.org_type == "SEH"
    input.delegatee.org_type == "AP"
}

# Pharmacy can only delegate to Pharmacy.
allow_bind if {
    binding_window_valid
    validate_patient_binding_pin

    input.delegator.org_type == "AP"
    input.delegatee.org_type == "AP"
}

# Specialist can delegate to specialist.
allow_bind if {
    binding_window_valid
    validate_patient_binding_pin

    input.delegator.org_type == "Specialist"
    input.delegatee.org_type == "Specialist"
}

# Specialist can delegate to pharmacy.
allow_bind if {
    binding_window_valid
    validate_patient_binding_pin

    input.delegator.org_type == "Specialist"
    input.delegatee.org_type == "AP"
}