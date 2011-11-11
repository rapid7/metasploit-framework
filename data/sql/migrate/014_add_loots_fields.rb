class AddLootsFields < ActiveRecord::Migration
	def self.up
		add_column :loots, :name, :text
		add_column :loots, :info, :text
	end

	def self.down
		remove_column :loots, :name
		remove_column :loots, :info
	end
end

