# Test cases for bind scenarios. Focus on who can send to who

package pa.binding_test

import data.pa.binding

# Test passes when delegator and delegatee are both AP
test_ap_can_bind_ap if {
    binding.allow_bind with input as {
        "delegator": {
            "user_uzi_id": 123,
            "org_type": "AP",
            "user_level": "Head"
        },
        "delegatee": {
            "user_uzi_id": 456,
            "org_type": "AP",
            "user_level": "Head",
            "binding_pin": null
        },

        "reference": {
            "is_bound": false,
            "bound_user_uzi_id": null,
            "bound_user_role": null,
            "revoked": false,
            "can_copy": false,
            "expects_binding_pin": false,
            "binding_pin": null,
            "bind_expiry_window": [2027, 1, 1],
            "expiry": [2028, 1, 1],
            "document": "AMO",
            "allowed_permissions": ["Retrieve", "Pushback"]
        }
    }
}

# Test passes when binding is denied and binding expiry window expired
test_ap_can_bind_ap_but_bind_expiry_window if {
    not binding.allow_bind with input as {
        "delegator": {
            "user_uzi_id": 123,
            "org_type": "AP",
            "user_level": "Head"
        },
        "delegatee": {
            "user_uzi_id": 456,
            "org_type": "AP",
            "user_level": "Head",
            "binding_pin": null
        },

        "reference": {
            "is_bound": false,
            "bound_user_uzi_id": null,
            "bound_user_role": null,
            "revoked": false,
            "can_copy": false,
            "expects_binding_pin": false,
            "binding_pin": null,
            "bind_expiry_window": [2024, 1, 1],
            "expiry": [2028, 1, 1],
            "document": "AMO",
            "allowed_permissions": ["Retrieve", "Pushback"]
        }
    }
}

# Test passes since delegator.org_type is pharmacy and delegetee
# org type is specialist, which is not allowed
test_ap_cannot_bind_specialist if {
    not binding.allow_bind with input as {
        "delegator": {
            "user_uzi_id": 123,
            "org_type": "AP",
            "user_level": "Head"
        },
        "delegatee": {
            "user_uzi_id": 456,
            "org_type": "SPEC",
            "user_level": "Head",
            "binding_pin": null
        },

        "reference": {
            "is_bound": false,
            "bound_user_uzi_id": null,
            "bound_user_role": null,
            "revoked": false,
            "can_copy": false,
            "expects_binding_pin": false,
            "binding_pin": null,
            "bind_expiry_window": [2027, 1, 1],
            "expiry": [2028, 1, 1],
            "document": "AMO",
            "allowed_permissions": ["Retrieve", "Pushback"]
        }
    }
}



# Test passes since delegator and delegatee are both AP
# and the correct binding_pin has been used.
test_correct_pin if {
    binding.allow_bind with input as {
        "delegator": {
            "user_uzi_id": 123,
            "org_type": "AP",
            "user_level": "Head"
        },
        "delegatee": {
            "user_uzi_id": 456,
            "org_type": "AP",
            "user_level": "Head",
            "binding_pin": 987
        },

        "reference": {
            "is_bound": false,
            "bound_user_uzi_id": null,
            "bound_user_role": null,
            "revoked": false,
            "can_copy": false,
            "expects_binding_pin": true,
            "binding_pin": 987,
            "bind_expiry_window": [2027, 1, 1],
            "expiry": [2028, 1, 1],
            "document": "AMO",
            "allowed_permissions": ["Retrieve", "Pushback"]
        }
    }
}


# Test passes as binding is not allowed because of an incorrect pin
test_incorrect_pin if {
    not binding.allow_bind with input as {
        "delegator": {
            "user_uzi_id": 123,
            "org_type": "AP",
            "user_level": "Head"
        },
        "delegatee": {
            "user_uzi_id": 456,
            "org_type": "AP",
            "user_level": "Head",
            "binding_pin": 12345678
        },

        "reference": {
            "is_bound": false,
            "bound_user_uzi_id": null,
            "bound_user_role": null,
            "revoked": false,
            "can_copy": false,
            "expects_binding_pin": true,
            "binding_pin": 987,
            "bind_expiry_window": [2027, 1, 1],
            "expiry": [2028, 1, 1],
            "document": "AMO",
            "allowed_permissions": ["Retrieve", "Pushback"]
        }
    }
}

