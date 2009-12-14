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

		w = Msf::DBManager::Workspace.default
		Msf::DBManager::Host.update_all ["workspace_id = ?", w.id]
	end

	def self.down
		drop_table :workspaces

		change_table :hosts do |t|
			t.remove   :workspace_id
		end

		add_index :hosts, :address, :unique => true
	end

end