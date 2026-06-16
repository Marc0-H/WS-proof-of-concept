package pa.binding

default allow_bind := false

# Check if this is a first-time access attempt and if the reference is late-bound
# If current time falls outside the binding window, return false.
binding_window_valid if {
    input.reference.is_bound
}

binding_window_valid if {
    not input.reference.is_bound
    time.date(time.now_ns()) <= input.reference.bind_expiry_window
}




# Check if this is a first-time access attempt and if an access code is expected.
# In case the reference is already bound or no access code is expected, return true.
validate_patient_access_code if {
    input.reference.is_bound
}

validate_patient_access_code if {
    not input.reference.is_bound
    input.reference.expects_access_code == false
}

validate_patient_access_code if {
    not input.reference.is_bound
    input.reference.expects_access_code == true
    input.reference.access_code == input.delegatee.access_code
}



# HA can delegate to anyone
allow_bind if {
    binding_window_valid
    validate_patient_access_code

    input.delegator.org_type == "HA"
}

# HAP can delegate to anyone except Specialists
allow_bind if {
    binding_window_valid
    validate_patient_access_code

    input.delegator.org_type == "HAP"
    input.delegatee.org_type != "Specialist"
}

# SEH can delegate to specialist or pharmacy
allow_bind if {
    binding_window_valid
    validate_patient_access_code

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
    validate_patient_access_code

    input.delegator.org_type == "AP"
    input.delegatee.org_type == "AP"
}

# Specialist can delegate to specialist.
allow_bind if {
    binding_window_valid
    validate_patient_access_code

    input.delegator.org_type == "Specialist"
    input.delegatee.org_type == "Specialist"
}

# Specialist can delegate to pharmacy.
allow_bind if {
    binding_window_valid
    validate_patient_access_code

    input.delegator.org_type == "Specialist"
    input.delegatee.org_type == "AP"
}