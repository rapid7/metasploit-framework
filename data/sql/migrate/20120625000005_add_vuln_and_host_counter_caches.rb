class AddVulnAndHostCounterCaches < ActiveRecord::Migration

  def self.up
    add_column :hosts, :host_detail_count, :integer, :default => 0
  
    Mdm::Host.reset_column_information
    Mdm::Host.all.each do |h|
      Mdm::Host.reset_counters h.id, :host_detail_count
    end

    add_column :vulns, :vuln_detail_count, :integer, :default => 0
    add_column :vulns, :vuln_attempt_count, :integer, :default => 0
  
    Mdm::Vuln.reset_column_information
    Mdm::Vuln.all.each do |h|
      Mdm::Vuln.reset_counters h.id, :vuln_detail_count
      Mdm::Vuln.reset_counters h.id, :vuln_attempt_count
    end

  end

  def self.down
    remove_column :hosts, :host_detail_count
    remove_column :vulns, :vuln_detail_count
    remove_column :vulns, :vuln_attempt_count
  end
end
