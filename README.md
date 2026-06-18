# Proof of concept

This repo shows an implementation of policies needed for a push authorisation system in both Rego and Cedar.

## Rego

example test: opa test tests/late_bind_test.rego general_binding_and_delegation_policy.rego

## Cedar

example test: cedar authorize --policies general_binding_and_delegation_policy.cedar --entities tests/spec_cannot_bind_ap/entities.json --request-json tests/spec_cannot_bind_ap/request.json
