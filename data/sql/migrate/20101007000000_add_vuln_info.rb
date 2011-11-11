class AddVulnInfo < ActiveRecord::Migration
	def self.up
		add_column :web_vulns, :category, :text
		add_column :web_vulns, :confidence, :text		
		add_column :web_vulns, :description, :text
		add_column :web_vulns, :blame, :text
	end
	def self.down
		remove_column :web_forms, :category
		remove_column :web_vulns, :confidence
		remove_column :web_vulns, :description
		remove_column :web_vulns, :blame		
	end
end

