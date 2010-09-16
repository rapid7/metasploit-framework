class RequireAdminFlag < ActiveRecord::Migration

	# Make the admin flag required.
	def self.up
		# update any existing records
		User.find_each { |u| u.admin = true if u.admin.nil? }

		change_column :users, :admin, :boolean, :null => false, :default => true
	end

	def self.down
		change_column :users, :admin, :boolean, :default => true
	end

end
