class AddLootsCtype < ActiveRecord::Migration
	def self.up
		add_column :loots, :content_type, :string
	end

	def self.down
		remove_column :loots, :content_type
	end
end

