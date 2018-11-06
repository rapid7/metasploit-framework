class AddSettingsToTasksTable < ActiveRecord::Migration

	def self.up
		add_column :tasks, :settings, :binary
	end

	def self.down
		remove_column :tasks, :settings
	end

end

