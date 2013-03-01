class AddScopeToHosts < ActiveRecord::Migration
  def self.up
    add_column :hosts, :scope, :text
  end

  def self.down
    remove_column :hosts, :scope
  end
end
