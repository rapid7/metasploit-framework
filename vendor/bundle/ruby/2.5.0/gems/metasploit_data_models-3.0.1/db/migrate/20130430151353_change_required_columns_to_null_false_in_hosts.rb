# Changes all the {COLUMNS} in the hosts table that are required for {Mdm::Host}, but were previously `:null => true`.
class ChangeRequiredColumnsToNullFalseInHosts < MetasploitDataModels::ChangeRequiredColumnsToNullFalse
  # Columns that were previously `:null => true`, but are actually required to be non-null, so should be
  # `:null => false`
  COLUMNS = [
      :address,
      :workspace_id
  ]
  # Table in which {COLUMNS} are.
  TABLE_NAME = :hosts
end
