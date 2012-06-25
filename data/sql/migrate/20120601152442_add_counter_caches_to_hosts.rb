class AddCounterCachesToHosts < ActiveRecord::Migration

  def self.up
    add_column :hosts, :note_count, :integer, :default => 0
    add_column :hosts, :vuln_count, :integer, :default => 0
    add_column :hosts, :service_count, :integer, :default => 0
  end

  def self.down
    remove_column :hosts, :note_count
    remove_column :hosts, :vuln_count
    remove_column :hosts, :service_count
  end
end
