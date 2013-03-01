class AddWorkspaceUserInfo < ActiveRecord::Migration
	def self.up
		change_table :workspaces do |t|
			t.string :boundary, :limit => 4096
		end

		change_table :users do |t|
			t.string :fullname
			t.string :email
			t.string :phone
            t.string :company
		end
	end

	def self.down
		change_table :workspaces do |t|
			t.remove :boundary
		end

		change_table :users do |t|
			t.remove :fullname
			t.remove :email
			t.remove :phone
            t.remove :company
		end
	end

end

