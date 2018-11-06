class RemovePnameValidation < ActiveRecord::Migration

  def change
		change_column :web_vulns, :pname, :text, :null => true
  end

end
