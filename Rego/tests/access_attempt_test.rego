# Test cases for access attempts scenarios

package pa.access_attempt_test

import data.pa.access

# Test passes when access is allowed and bound user id == delegatee.user_id
test_correct_id if {
    access.allow_access with input as {
        "delegator": {
            "user_uzi_id": 123,
            "org_type": "AP"
        },
        "delegatee": {
            "user_uzi_id": 456,
            "org_type": "AP",
            "binding_pin": null
        },

        "reference": {
            "is_bound": true,
            "bound_user_uzi_id": 456,
            "bound_user_role": "AP",
            "revoked": false,
            "can_copy": false,
            "expects_binding_pin": false,
            "binding_pin": null,
            "bind_expiry_window": [2027, 1, 1],
            "expiry": [2028, 1, 1],
            "document": "AMO",
            "allowed_permissions": ["retrieve", "pushback"]
        }
    }
}



# Test passes when access is denied and bound user id != delegatee.user_id
test_incorrect_id if {
    not access.allow_access with input as {
        "delegator": {
            "user_uzi_id": 123,
            "org_type": "AP"
        },
        "delegatee": {
            "user_uzi_id": 456,
            "org_type": "AP",
            "binding_pin": null
        },

        "reference": {
            "is_bound": true,
            "bound_user_uzi_id": 98765,
            "bound_user_role": "AP",
            "revoked": false,
            "can_copy": false,
            "expects_binding_pin": false,
            "binding_pin": null,
            "bind_expiry_window": [2027, 1, 1],
            "expiry": [2028, 1, 1],
            "document": "AMO",
            "allowed_permissions": ["retrieve", "pushback"]
        }
    }
}



# Test passes when reference is revoked and access denied
test_revoked if {
    not access.allow_access with input as {
        "delegator": {
            "user_uzi_id": 123,
            "org_type": "AP"
        },
        "delegatee": {
            "user_uzi_id": 456,
            "org_type": "AP",
            "binding_pin": null
        },

        "reference": {
            "is_bound": true,
            "bound_user_uzi_id": 456,
            "bound_user_role": "AP",
            "revoked": true,
            "can_copy": false,
            "expects_binding_pin": false,
            "binding_pin": null,
            "bind_expiry_window": [2027, 1, 1],
            "expiry": [2028, 1, 1],
            "document": "AMO",
            "allowed_permissions": ["retrieve", "pushback"]
        }
    }
}


# Test passes when reference is expired and access denied
test_expired if {
    not access.allow_access with input as {
        "delegator": {
            "user_uzi_id": 123,
            "org_type": "AP"
        },
        "delegatee": {
            "user_uzi_id": 456,
            "org_type": "AP",
            "binding_pin": null
        },

        "reference": {
            "is_bound": true,
            "bound_user_uzi_id": 456,
            "bound_user_role": "AP",
            "revoked": false,
            "can_copy": false,
            "expects_binding_pin": false,
            "binding_pin": null,
            "bind_expiry_window": [2024, 1, 1],
            "expiry": [2025, 1, 1],
            "document": "AMO",
            "allowed_permissions": ["retrieve", "pushback"]
        }
    }
}