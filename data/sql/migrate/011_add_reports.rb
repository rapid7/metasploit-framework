class AddReports < ActiveRecord::Migration

	def self.up
		create_table :reports do |t|
			t.integer   :workspace_id, :null => false, :default => 1
			t.string    :created_by
			t.string    :rtype
			t.string    :path, :limit  => 1024
			t.text      :options
			t.timestamps
		end
	end

	def self.down
		drop_table :reports
	end

end

