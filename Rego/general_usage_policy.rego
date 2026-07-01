package pa.usage

default allow_usage := false

default basic_access_requirements_satisfied := false
default role_and_document_mapping_satisfied := false

# Certain roles are allowed to view certain documents
allowed_documents := {
    "AP":   {"AMO"},
    "SPEC": {"AMO"},
    "HA":   {"NHG-PS", "Mini-PS", "AMO"},
    "HAP":  {"NHG-PS", "Mini-PS", "AMO"},
    "SEH":  {"Mini-PS", "AMO"}
}

# If one of requirements below is not satisfied, deny by default
basic_access_requirements_satisfied if {
    input.reference.is_bound == true
    input.delegatee.user_uzi_id == input.reference.bound_user_uzi_id
    input.reference.revoked == false
    input.reference.expiry > time.date(time.now_ns())
}

# If role and document type do not adhere to the mapping, deny by default.
role_and_document_mapping_satisfied if {
    role := input.delegatee.org_type
    input.reference.document in allowed_documents[role]

}

# Action is Retrieve (read) or Pushback (modify) document
allow_usage if {
    basic_access_requirements_satisfied
    role_and_document_mapping_satisfied
    input.action in {"Retrieve", "Pushback"}
    input.action in input.reference.allowed_permissions
}

# Action is to delegate / copy reference
allow_usage if {
    basic_access_requirements_satisfied
    input.action == "Copy"
    input.reference.can_copy == true
}

