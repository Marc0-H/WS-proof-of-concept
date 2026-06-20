package pa.ap_usage_test

import data.pa.ap_usage

# Test passes when AP attempts to read AMO document and action is allowed
test_read_allowed if {
    ap_usage.allow_usage with input as {
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
            "allowed_permissions": ["Retrieve", "Pushback"]
        },

        "action": "Retrieve"
    }
}

# Test passes when action is denied since AP is not allowed to read NHG-PS
test_read_not_allowed if {
    not ap_usage.allow_usage with input as {
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
            "is_bound": true,
            "bound_user_uzi_id": 456,
            "bound_user_role": "AP",
            "revoked": false,
            "can_copy": false,
            "expects_binding_pin": false,
            "binding_pin": null,
            "bind_expiry_window": [2027, 1, 1],
            "expiry": [2028, 1, 1],
            "document": "NHG-PS",
            "allowed_permissions": ["Retrieve", "Pushback"]
        },

        "action": "Retrieve"
    }
}

# Test passes when user attempts copy action and can_copy==true
test_copy_allowed if {
    ap_usage.allow_usage with input as {
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
            "is_bound": true,
            "bound_user_uzi_id": 456,
            "bound_user_role": "AP",
            "revoked": false,
            "can_copy": true,
            "expects_binding_pin": false,
            "binding_pin": null,
            "bind_expiry_window": [2027, 1, 1],
            "expiry": [2028, 1, 1],
            "document": "AMO",
            "allowed_permissions": ["Retrieve", "Pushback"]
        },

        "action": "Copy"
    }
}