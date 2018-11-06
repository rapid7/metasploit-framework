class AddModuleFullNameToMatch < ActiveRecord::Migration
  def change
    add_column :automatic_exploitation_matches, :module_fullname, :text
    add_index :automatic_exploitation_matches, :module_fullname
  end
end
