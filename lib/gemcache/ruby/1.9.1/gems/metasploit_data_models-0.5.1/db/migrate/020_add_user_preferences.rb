class AddUserPreferences < ActiveRecord::Migration
	def self.up
		add_column :users, :prefs, :string, :limit => 524288
	end

	def self.down
		remove_column :users, :prefs
	end

end

