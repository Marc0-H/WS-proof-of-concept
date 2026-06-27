# Rego and Cedar example for policies in healthcare capability-based authorisation model.

Both Rego and Cedar implementations model the same delegation workflow and use the same example scenario and test cases.

The example demonstrates a healthcare delegation workflow involving:

- Healthcare Authority (HA)
- Specialist (SPEC)
- Pharmacy (AP)

The workflow is intentionally split into multiple authorization decisions to understand how delegation references can be bind and used. The workflow is as follows:

### Step 1: binding a late-bind reference

An HA creates a late-bind reference for a SPEC and additionally uses a required binding PIN. When the specialist attempts to use the reference, the general_binding_policy is used to evaluate whether the binding window is still valid, whether the binding PIN is correct and whether the HA is allowed to delegate to the specialist. If checks succeed, the reference can be bound to the SPEC.

### Step 2: copying the reference

The SPEC wants to create a delegated reference for a AP. The general_usage_policy is used to evaluated whether the reference is valid, the reference is bound to the requesting user and whether the reference permits the "copy" action. If allowed, the system can create a new reference.

### Step 3: Validating reference

The general_binding_policy is used again to validate the newly generated reference before it is distributed.

### Step 4: Using the generated reference

The AP uses the generated reference to read a "AMO" document. The general_usage_policy does the same checks as in step 2, but additionally checks whether AP is able to read the "AMO" document.

## Run scenario

To run this scenario and make the calls to the policy engines automatically, a python file is made available and can be run using the following command:
`python3 example_run.py`
The Python file should be run in their current location.

## Versions used

Cedar: 4.11.0
OPA: 1.16.2
Python: 3.14.6
