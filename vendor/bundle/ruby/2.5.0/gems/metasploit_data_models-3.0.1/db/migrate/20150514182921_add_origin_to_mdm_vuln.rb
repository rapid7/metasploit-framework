class AddOriginToMdmVuln < ActiveRecord::Migration
  def up
    add_column :vulns, :origin_id,   :integer
    add_column :vulns, :origin_type, :string

    add_index :vulns, :origin_id
  end

  def down
    remove_column :vulns, :origin_id
    remove_column :vulns, :origin_type
  end
end
