class ExpandDetails < ActiveRecord::Migration

	def self.up
		add_column :vuln_details, :nx_vuln_status, :text
		add_column :vuln_details, :nx_proof_key, :text
		add_column :vuln_details, :src, :string
		add_column :host_details, :src, :string
	end

	def self.down
		remove_column :vuln_details, :nx_vuln_status
		remove_column :vuln_details, :nx_proof_key
		remove_column :vuln_details, :src
		remove_column :host_details, :src
	end
end
