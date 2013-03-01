class AddAlertFields < ActiveRecord::Migration
	def self.up
		add_column :notes, :critical, :boolean
		add_column :notes, :seen, :boolean
		add_column :events, :critical, :boolean
		add_column :events, :seen, :boolean
	end

	def self.down
		remove_column :notes, :critical
		remove_column :notes, :seen
		remove_column :events, :critical
		remove_column :events, :seen
	end
end

