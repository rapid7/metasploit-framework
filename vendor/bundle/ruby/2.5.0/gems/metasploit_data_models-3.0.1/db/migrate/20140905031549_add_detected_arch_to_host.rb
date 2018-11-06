class AddDetectedArchToHost < ActiveRecord::Migration
  def change
    add_column :hosts, :detected_arch, :string, { :null => true }
  end
end
