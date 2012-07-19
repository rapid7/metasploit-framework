class AddLoggerAndPayloadToWebVulns < ActiveRecord::Migration

	def self.up
		add_column :web_vulns, :logger,  :string
		add_column :web_vulns, :payload, :text
	end

	def self.down
		remove_column :web_vulns, :logger
		remove_column :web_vulns, :payload
	end

end
