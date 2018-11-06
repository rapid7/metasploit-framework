class AddModuleRunFkToLoot < ActiveRecord::Migration
  def change
    change_table(:loots) do |t|
      t.integer :module_run_id
      t.index :module_run_id
    end
  end
end
