class AddOsFamilyToHosts < ActiveRecord::Migration
  def change
    add_column :hosts, :os_family, :string
  end
end
