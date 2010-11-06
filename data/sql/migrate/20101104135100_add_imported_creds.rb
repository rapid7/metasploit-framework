class AddImportedCreds < ActiveRecord::Migration

	def self.up
		create_table :imported_creds do |t|
			t.integer   :workspace_id, :null => false, :default => 1
			t.string    :user, :limit  => 512
			t.string    :pass, :limit  => 512
			t.string    :ptype, :limit  => 16, :default => "password"
		end
	end

	def self.down
		drop_table :imported_creds
	end

end

