class RenameUser < ActiveRecord::Migration
	def self.up
		remove_column :events, :user
		change_table :events do |t|
			t.string    :username
		end
	end

	def self.down
		remove_column :events, :username
		change_table :events do |t|
			t.string    :user
		end
	end
end

