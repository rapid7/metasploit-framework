class AddWorkspaces < ActiveRecord::Migration

	def self.up
		create_table :workspaces do |t|
			t.string    :name
			t.timestamps
		end

		change_table :hosts do |t|
			t.integer   :workspace_id, :required => true
		end

		remove_index :hosts, :column => :address

		#
		# This was broken after 018_add_workspace_user_info was introduced
		# because of the new boundary column.  For some reason, the
		# find_or_create_by_name that .default eventually calls here tries to
		# create a record with the boundary field that doesn't exist yet.  
		# See #1724
		#
		#w = Msf::DBManager::Workspace.default
		#Msf::DBManager::Host.update_all ["workspace_id = ?", w.id]
	end

	def self.down
		drop_table :workspaces

		change_table :hosts do |t|
			t.remove   :workspace_id
		end

		add_index :hosts, :address, :unique => true
	end

end
