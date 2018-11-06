class AddVulnIdToNote < ActiveRecord::Migration
  def change
    add_column :notes, :vuln_id, :integer
    add_index :notes, :vuln_id
  end
end
