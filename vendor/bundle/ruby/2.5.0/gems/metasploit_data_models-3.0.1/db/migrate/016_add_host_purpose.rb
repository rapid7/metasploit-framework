class AddHostPurpose < ActiveRecord::Migration
	def self.up
		add_column :hosts, :purpose, :text
	end

	def self.down
		remove_column :hosts, :purpose
	end
end

