class AddVirtualHostToHosts < ActiveRecord::Migration
  def self.up
    add_column :hosts, :virtual_host, :text
  end

  def self.down
    remove_column :hosts, :viritual_host
  end
end
