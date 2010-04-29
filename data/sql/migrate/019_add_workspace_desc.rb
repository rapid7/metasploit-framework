class AddWorkspaceDesc < ActiveRecord::Migration
	def self.up
		change_table :workspaces do |t|
			t.string :description, :limit => 4096
		end

		change_table :hosts do |t|
			t.string :comments, :limit => 4096
		end
	end

	def self.down
		change_table :workspaces do |t|
			t.remove :description
		end

		change_table :hosts do |t|
			t.remove :comments
		end
	end

end

