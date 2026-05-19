# Rego-to-CEL Conversion Guide

## Overview
This guide documents how Kubescape Rego controls in regolibrary are converted to
CEL ValidatingAdmissionPolicy resources in cel-admission-library.

## Conversion Pattern

### Rego (regolibrary)
```rego
deny[msga] {
    wl := input[_]
    wl.kind == "Deployment"
    wl.spec.template.spec.containers[_].securityContext.privileged == true
    msga := { "alertMessage": "...", ... }
}
```

### CEL equivalent (cel-admission-library)
```yaml
validations:
- expression: |
    object.spec.template.spec.containers.all(c,
      !has(c.securityContext) ||
      !has(c.securityContext.privileged) ||
      c.securityContext.privileged == false
    )
  message: "Privileged containers are not allowed"
```

## Key Differences

| Concept | Rego | CEL |
|---------|------|-----|
| Input | `input[_]` iterates all objects | `object` is the single resource |
| Iteration | `containers[_]` | `containers.all(c, ...)` |
| Field existence | implicit | `has(c.field)` required |
| Alert message | `msga.alertMessage` | `validations[].message` |
| Multi-kind | multiple `deny` blocks | multiple `resourceRules` entries |

## Controls Converted

| Control | Rego rule | CEL VAP | Status |
|---------|-----------|---------|--------|
| C-0013 | non-root-containers | kubescape-c-0013-deny-resources-with-non-root-user-not-set | ✅ Done |
| C-0016 | allow-privilege-escalation | kubescape-c-0016-allow-privilege-escalation | ✅ Done |
| C-0017 | immutable-container-filesystem | kubescape-c-0017-deny-resources-with-mutable-container-filesystem | ✅ Done |
| C-0034 | automount-service-account | kubescape-c-0034-deny-resources-with-automount-service-account-token-enabled | ✅ Done |
| C-0057 | privileged-container | kubescape-c-0057-privileged-container-denied | ✅ Done |

## Steps to Convert a New Control

1. Find the Rego rule in `rules/<rule-name>/raw.rego`
2. Identify the `deny` block conditions
3. Translate each condition to a CEL `validations[]` expression
4. Add `has()` guards for every optional field
5. Write `policy.yaml` + `rule.metadata.json` in cel-admission-library
6. Test with `python3 scripts/run-control-tests.py` from the control directory
