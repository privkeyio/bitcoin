Transaction relay and mining policy
----------------------------------

- Ephemeral-dust transactions may have negative modified fees from the
  calculated sub-dust fee penalty. Actual fees and manual fee deltas must
  remain zero; the child must cover the penalty in package fee evaluation.
  The penalty follows the configured dust relay rate and output values.
  Policy defaults, `corepolicy` overrides, and existing dust and package
  restrictions are unchanged. The intended version-3 parent/child anchor
  packages require `-mempooltruc=enforce`. (#438)
