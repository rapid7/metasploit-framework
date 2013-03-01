class AddNameToNexposeConsolesTable < ActiveRecord::Migration

	def self.up
		add_column :nexpose_consoles, :name, :text
	end

	def self.down
		remove_column :nexpose_consoles, :name
	end

end

