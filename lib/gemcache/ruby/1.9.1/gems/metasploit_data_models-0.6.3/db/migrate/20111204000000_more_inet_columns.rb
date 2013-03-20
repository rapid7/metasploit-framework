class MoreInetColumns < ActiveRecord::Migration

	def self.up
		change_column :wmap_requests, :address, 'INET using address::INET'
		remove_column :wmap_requests, :address6
		change_column :wmap_targets, :address, 'INET using address::INET'
		remove_column :wmap_targets, :address6		
	end

	def self.down
		change_column :wmap_requests, :address, :string, :limit => 16
		add_column :wmap_requests, :address6, :string, :limit => 255
		change_column :wmap_targets, :address, :string, :limit => 16
		add_column :wmap_targets, :address6, :string, :limit => 255
	end

end
