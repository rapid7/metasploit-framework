class RequireAdminFlag < ActiveRecord::Migration

	# Make the admin flag required.
	def self.up
		# update any existing records
		Mdm::User.update_all({:admin => true}, {:admin => nil})

		change_column :users, :admin, :boolean, :null => false, :default => true
	end

	def self.down
		change_column :users, :admin, :boolean, :default => true
	end

end
