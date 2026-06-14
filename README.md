## Objective

The objective of this fork is to validate security mutation operators defined in a research study, by assessing whether the existing test suite can detect them.

The implemented tests were added in the class `AutoMutSecTestsThatCanCaptureMutantsTest`, focusing on security-related mutations in Spring Security authorization rules.

## Scope

The tests target mutation operators such as ISIR, PARO, and LNSO applied to `@PreAuthorize` expressions, verifying whether changes in authorization logic are detected through HTTP response behavior.
