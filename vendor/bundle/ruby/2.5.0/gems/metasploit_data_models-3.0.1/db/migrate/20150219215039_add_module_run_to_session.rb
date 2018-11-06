class AddModuleRunToSession < ActiveRecord::Migration
  def change
    change_table :sessions do |t|
      t.integer :module_run_id
    end
    add_index :sessions, :module_run_id
  end
end
