class AddNotesToCreds < ActiveRecord::Migration

	def self.up
		add_column :creds, :note_id, :integer
		add_column :notes, :cred_id, :integer
	end

	def self.down
		remove_column :creds, :note_id
		remove_column :notes, :cred_id
	end
end
