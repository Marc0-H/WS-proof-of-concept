# example_run.py (CEDAR version)

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


def cedar_eval(policy_file, entities_file, request_file):
    cmd = [
        "cedar",
        "authorize",
        "--policies",
        policy_file,
        "--entities",
        entities_file,
        "--request-json",
        request_file,
        "--schema",
        "schema.cedarschema"
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )

    print(result.stdout)
    print(result.stderr)

    return result.stdout.strip()


def print_step(title):
    print("\n" + "-" * 80)
    print(title)
    print("-" * 80)


def is_allow(result: str) -> bool:
    return "ALLOW" in result


def main():
    # STEP 1
    # Specialist attempts to bind the late-bound reference.


    print_step("STEP 1 - Can Specialist bind HA reference?")

    can_bind = cedar_eval(
        "general_binding_policy.cedar",
        "tests_for_example_case/step_1/entities.json",
        "tests_for_example_case/step_1/request.json",
    )

    print("Result:", can_bind)

    if not is_allow(can_bind):
        print("Binding denied")
        return

    print("Binding allowed")

    # STEP 2
    # Specialist wants to copy the reference to AP.

    print_step("STEP 2 - Can Specialist perform COPY action?")

    can_copy = cedar_eval(
        "general_usage_policy.cedar",
        "tests_for_example_case/step_2/entities.json",
        "tests_for_example_case/step_2/request.json",
    )

    print("Result:", can_copy)

    if not is_allow(can_copy):
        print("Copy denied")
        return

    print("Copy allowed")


    # STEP 3
    # System creates new pre-bind reference.
    # Validate generated reference.
    print_step("STEP 3 - Validate generated reference")

    reference_valid = cedar_eval(
        "general_binding_policy.cedar",
        "tests_for_example_case/step_3/entities.json",
        "tests_for_example_case/step_3/request.json",
    )

    print("Result:", reference_valid)

    if not is_allow(reference_valid):
        print("Reference invalid")
        return

    print("Reference valid")

    # STEP 4
    # AP later uses the generated reference.
    print_step("STEP 4 - Can AP read AMO?")

    can_read = cedar_eval(
        "general_usage_policy.cedar",
        "tests_for_example_case/step_4/entities.json",
        "tests_for_example_case/step_4/request.json",
    )

    print("Result:", can_read)

    if not is_allow(can_read):
        print("Read denied")
        return

    print("Read allowed.")

    print("Scenario completed.")


if __name__ == "__main__":
    main()