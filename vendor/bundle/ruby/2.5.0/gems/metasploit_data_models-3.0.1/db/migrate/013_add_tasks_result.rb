class AddTasksResult < ActiveRecord::Migration
	def self.up
		add_column :tasks, :result, :text
	end

	def self.down
		remove_column :tasks, :result
	end
end

