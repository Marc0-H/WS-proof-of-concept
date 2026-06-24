package pa.usage

default allow_usage := false

default basic_access_requirements_satisfied := false

# If one of requirements below is not satisfied, deny by default
basic_access_requirements_satisfied if {
    input.reference.is_bound == true
    input.delegatee.user_uzi_id == input.reference.bound_user_uzi_id
    input.reference.revoked == false
    input.reference.expiry > time.date(time.now_ns())
}



#
# IF PHARMACIST
#

# Allow pharmacist to read if document type is AMO.
allow_usage if {
    basic_access_requirements_satisfied
    input.delegatee.org_type = "AP"
    input.action == "Retrieve"
    input.action in input.reference.allowed_permissions
    input.reference.document == "AMO"
}

# Allow pharmacist to pushback in document type is AMO
allow_usage if {
    basic_access_requirements_satisfied
    input.delegatee.org_type = "AP"
    input.action == "Pushback"
    input.action in input.reference.allowed_permissions
    input.reference.document == "AMO"
}

# Allow pharmacist to delegate if they are allowed to by the reference
allow_usage if {
    basic_access_requirements_satisfied
    input.delegatee.org_type = "AP"
    input.action == "Copy"
    input.reference.can_copy == true
}



#
# IF SPECIALIST
#

# Allow specialist to read if document type is AMO.
allow_usage if {
    basic_access_requirements_satisfied
    input.delegatee.org_type = "SPEC"
    input.action == "Retrieve"
    input.action in input.reference.allowed_permissions
    input.reference.document == "AMO"
}

# Allow specialist to pushback in document type is AMO
allow_usage if {
    basic_access_requirements_satisfied
    input.delegatee.org_type = "SPEC"
    input.action == "Pushback"
    input.action in input.reference.allowed_permissions
    input.reference.document == "AMO"
}

# Allow specialist to delegate if they are allowed to by the reference
allow_usage if {
    basic_access_requirements_satisfied
    input.delegatee.org_type = "SPEC"
    input.action == "Copy"
    input.reference.can_copy == true
}



#
# IF 'HUISARTS'
#

# Allow HA to read if document type is NHG-PS, Mini-PS, AMO.
allow_usage if {
    basic_access_requirements_satisfied
    input.delegatee.org_type = "HA"
    input.action == "Retrieve"
    input.action in input.reference.allowed_permissions
    input.reference.document in ["NHG-PS", "Mini-PS", "AMO"]
}

# Allow HA to pushback if document type is NHG-PS, Mini-PS, AMO.
allow_usage if {
    basic_access_requirements_satisfied
    input.delegatee.org_type = "HA"
    input.action == "Pushback"
    input.action in input.reference.allowed_permissions
    input.reference.document in ["NHG-PS", "Mini-PS", "AMO"]
}

# Allow HA to delegate if they are allowed to by the reference
allow_usage if {
    basic_access_requirements_satisfied
    input.delegatee.org_type = "HA"
    input.action == "Copy"
    input.reference.can_copy == true
}


#
# IF 'HUISARTSENPOST'
#

# Allow HAP to read if document type is NHG-PS, Mini-PS, AMO.
allow_usage if {
    basic_access_requirements_satisfied
    input.delegatee.org_type = "HAP"
    input.action == "Retrieve"
    input.action in input.reference.allowed_permissions
    input.reference.document in ["NHG-PS", "Mini-PS", "AMO"]
}

# Allow HAP to pushback if document type is NHG-PS, Mini-PS, AMO.
allow_usage if {
    basic_access_requirements_satisfied
    input.delegatee.org_type = "HAP"
    input.action == "Pushback"
    input.action in input.reference.allowed_permissions
    input.reference.document in ["NHG-PS", "Mini-PS", "AMO"]
}

# Allow HAP to delegate if they are allowed to by the reference
allow_usage if {
    basic_access_requirements_satisfied
    input.delegatee.org_type = "HAP"
    input.action == "Copy"
    input.reference.can_copy == true
}



#
# IF 'SPOED EISENDE HULP'
#

# Allow SEH to read if document type is Mini-PS or AMO.
allow_usage if {
    basic_access_requirements_satisfied
    input.delegatee.org_type = "SEH"
    input.action == "Retrieve"
    input.action in input.reference.allowed_permissions
    input.reference.document in ["Mini-PS", "AMO"]
}

# Allow SEH to pushback if document type is Mini-PS or AMO.
allow_usage if {
    basic_access_requirements_satisfied
    input.delegatee.org_type = "SEH"
    input.action == "Pushback"
    input.action in input.reference.allowed_permissions
    input.reference.document in ["Mini-PS", "AMO"]
}

# Allow SEH to delegate if they are allowed to by the reference or AMO
allow_usage if {
    basic_access_requirements_satisfied
    input.delegatee.org_type = "SEH"
    input.action == "Copy"
    input.reference.can_copy == true
}



