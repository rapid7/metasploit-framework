class AddCredFileTable < ActiveRecord::Migration

	def self.up
		create_table :cred_files do |t|
			t.integer :workspace_id, :null => false, :default => 1
			t.string :path, :limit => 1024
			t.string :ftype, :limit => 16
			t.string :created_by
			t.string :name, :limit => 512
			t.string :desc, :limit => 1024

			t.timestamps
		end
	end

	def self.down
		drop_table :cred_files
	end

end
