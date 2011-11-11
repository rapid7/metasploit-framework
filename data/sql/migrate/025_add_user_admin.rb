class AddUserAdmin < ActiveRecord::Migration

	# Add user admin flag and project member list.
	def self.up
		add_column :users, :admin, :boolean, :default => true

		create_table :project_members, :id => false do |t|
			t.integer :workspace_id, :null => false
			t.integer :user_id, :null => false
		end
	end

	def self.down
		remove_column :users, :admin

		drop_table :project_members
	end
end

