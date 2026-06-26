# example_run.py (Rego version)

# This python file goes through an example run of a practical scenario
# Scenario is as follows:
# HA creates late-bind reference to specialist and sets a binding pin
# Specialist uses reference and attempts to bind
# Binding is allowed and system continues to check if the action that specialist
# wants to perform is allowed (action == copy to AP).
# The copy action is allowed and the system creates the requested pre-bind reference.
# The system checks if the pre-bind reference satisfies the requirements
# Once the AP uses the reference, the system checks if ap can perform the action (Read AMO)


import json
import subprocess
from pathlib import Path

# ROOT = Path().resolve()
# POLICY_DIR = ROOT / "tests_for_example_case"


def opa_eval(query, input_file, policy_file):
    """
    Execute an opa query and return the result.
    """

    cmd = [
        "opa",
        "eval",
        "--format=json",
        "-d",
        policy_file,
        "-i",
        input_file,
        query,
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=True,
    )

    pl = json.loads(result.stdout)

    return pl["result"][0]["expressions"][0]["value"]


def print_step(title):
    print()
    print("-" * 80)
    print(title)
    print("-" * 80)

def main():
    # STEP 1
    # Specialist attempts to bind the late-bound reference.


    print_step("STEP 1 - Can Specialist bind HA reference?")

    can_bind = opa_eval(
        "data.pa.binding.allow_bind",
        "tests_for_example_case/can_spec_late_bind_to_ha_ref_scenario.json",
        "general_binding_policy.rego"
    )

    print(f"allow_bind = {can_bind}")

    if not can_bind:
        print("Binding denied.")
        return

    print("Binding allowed.")

    # STEP 2
    # Specialist wants to copy the reference to AP.

    print_step("STEP 2 - Can Specialist perform COPY action?")

    can_copy = opa_eval(
        "data.pa.usage.allow_usage",
        "tests_for_example_case/spec_wants_to_delegate_scenario.json",
        "general_usage_policy.rego"
    )

    print(f"allow_usage = {can_copy}")

    if not can_copy:
        print("Copy denied.")
        return

    print("Copy allowed.")

    # STEP 3
    # System creates new pre-bind reference.
    # Validate generated reference.

    print_step("STEP 3 - Validate generated reference")

    reference_valid = opa_eval(
        "data.pa.binding.allow_bind",
        "tests_for_example_case/system_ha_checks_if_can_create_pre_bind_requested_by_ap.json",
        "general_binding_policy.rego"
    )
    print(
        f"allow_bind = "
        f"{reference_valid}"
    )

    if not reference_valid:
        print("Reference validation failed.")
        return

    print("Reference valid.")



    # STEP 4
    # AP later uses the generated reference.

    print_step("STEP 4 - Can AP read AMO?")

    can_read = opa_eval(
        "data.pa.usage.allow_usage",
        "tests_for_example_case/system_ha_checks_if_ap_can_perform_action.json",
        "general_usage_policy.rego"
    )

    print(f"allow_usage = {can_read}")

    if not can_read:
        print("Read denied.")
        return

    print("Read allowed.")

    print()
    print("Scenario completed.")


if __name__ == "__main__":
    main()
