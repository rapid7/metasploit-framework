class AddVulnAndHostCounterCaches < ActiveRecord::Migration

  def self.up
    add_column :hosts, :host_detail_count, :integer, :default => 0
    add_column :vulns, :vuln_detail_count, :integer, :default => 0
    add_column :vulns, :vuln_attempt_count, :integer, :default => 0
  end

  def self.down
    remove_column :hosts, :host_detail_count
    remove_column :vulns, :vuln_detail_count
    remove_column :vulns, :vuln_attempt_count
  end
end
