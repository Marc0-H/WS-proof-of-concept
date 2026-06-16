# Test cases for late-bind scenarios.

package pa.binding_test

import data.pa.binding

# Test passes since delegator.org_type is pharmacy and delegetee
# org type is pharmacy
test_ap_can_bind_ap if {
    binding.allow_bind with input as {
        "delegator": {
            "user_id": 123,
            "org_type": "AP"
        },
        "delegatee": {
            "user_id": 456,
            "org_type": "AP",
            "provided_code": null
        },

        "reference": {
            "is_bound": false,
            "bound_user_id": null,
            "revoked": false,
            "can_copy": false,
            "expects_access_code": false,
            "access_code": null,
            "bind_expiry_window": [2027, 1, 1],
            "expiry": [2028, 1, 1]
        }
    }
}

# Test passes since user is not allowed to bind because bind access is
# outside bind expiry window
test_ap_can_bind_ap_but_bind_expiry_window if {
    not binding.allow_bind with input as {
        "delegator": {
            "user_id": 123,
            "org_type": "AP"
        },
        "delegatee": {
            "user_id": 456,
            "org_type": "AP",
            "provided_code": null
        },

        "reference": {
            "is_bound": false,
            "bound_user_id": null,
            "revoked": false,
            "can_copy": false,
            "expects_access_code": false,
            "access_code": null,
            "bind_expiry_window": [2024, 1, 1],
            "expiry": [2028, 1, 1]
        }
    }
}

# Test passes since delegator.org_type is pharmacy and delegetee
# org type is specialist, which is not allowed
test_ap_cannot_bind_specialist if {
    not binding.allow_bind with input as {
        "delegator": {
            "caller_id": 123,
            "caller_type": "AP"
        },
        "delegatee": {
            "user_id": 456,
            "org_type": "Specialist",
            "provided_code": null
        },

        "reference": {
            "is_bound": false,
            "bound_user_id": null,
            "revoked": false,
            "can_copy": false,
            "expects_access_code": false,
            "access_code": null,
            "bind_expiry_window": [2027, 1, 1],
            "expiry": [2028, 1, 1]
        }
    }
}

