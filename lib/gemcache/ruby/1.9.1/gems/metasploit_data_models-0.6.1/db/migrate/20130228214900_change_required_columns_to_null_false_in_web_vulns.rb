# Changes all the {COLUMNS} in the web_vulns table that are required for {Mdm::WebVuln}, but were previously
# :null => true
class ChangeRequiredColumnsToNullFalseInWebVulns < ActiveRecord::Migration
  # Columns that were previously :null => true, but are actually required to be non-null, so should be
  # :null => false
  COLUMNS = [
      :category,
      :confidence,
      :method,
      :name,
      :params,
      :path,
      :pname,
      :proof,
      :risk
  ]
  # Table in which {COLUMNS} are.
  TABLE_NAME = :web_vulns

  # Marks all the {COLUMNS} as :null => true
  def down
    COLUMNS.each do |column|
      change_column_null(TABLE_NAME, column, true)
    end
  end

  # Marks all the {COLUMNS} as :null => false
  def up
    COLUMNS.each do |column|
      change_column_null(TABLE_NAME, column, false)
    end
  end


end
