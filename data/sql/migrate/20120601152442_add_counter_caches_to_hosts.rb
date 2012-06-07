class AddCounterCachesToHosts < ActiveRecord::Migration

  def self.up
    add_column :hosts, :note_count, :integer, :default => 0
    add_column :hosts, :vuln_count, :integer, :default => 0
    add_column :hosts, :service_count, :integer, :default => 0
  
    Mdm::Host.reset_column_information
    Mdm::Host.all.each do |h|
      Mdm::Host.reset_counters h.id, :notes
      Mdm::Host.reset_counters h.id, :vulns
      Mdm::Host.reset_counters h.id, :services
    end
  end

  def self.down
    remove_column :hosts, :note_count
    remove_column :hosts, :vuln_count
    remove_column :hosts, :service_count
  end
end