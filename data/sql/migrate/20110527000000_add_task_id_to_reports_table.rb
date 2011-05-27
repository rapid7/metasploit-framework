class AddTaskIdToReportsTable < ActiveRecord::Migration

	def self.up
		add_column :reports, :task_id, :integer
	end

	def self.down
		remove_column :reports, :task_id
	end

end
