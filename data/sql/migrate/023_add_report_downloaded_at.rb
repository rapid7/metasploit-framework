class AddReportDownloadedAt < ActiveRecord::Migration
	def self.up
		add_column :reports, :downloaded_at, :timestamp
	end

	def self.down
		remove_column :reports, :downloaded_at
	end
end

