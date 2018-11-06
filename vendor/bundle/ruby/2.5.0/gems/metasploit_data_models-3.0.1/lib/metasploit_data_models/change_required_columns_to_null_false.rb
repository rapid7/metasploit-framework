# Changes all the COLUMNS in the table with TABLE_NAME that are required from the table's mode, but were previously
# `:null => true`, to `:null => false`.
#
#  @abstract Subclass and define COLUMNS as Array<Symbol> and TABLE_NAME as Symbol.
class MetasploitDataModels::ChangeRequiredColumnsToNullFalse < ActiveRecord::Migration
  # Marks all the COLUMNS as `:null => true`
  def down
    # Use self.class:: so constants are resolved in subclasses instead of this class.
    self.class::COLUMNS.each do |column|
      change_column_null(self.class::TABLE_NAME, column, true)
    end
  end

  # Marks all the COLUMNS as `:null => false`
  def up
    # Use self.class:: so constants are resolved in subclasses instead of this class.
    self.class::COLUMNS.each do |column|
      change_column_null(self.class::TABLE_NAME, column, false)
    end
  end
end