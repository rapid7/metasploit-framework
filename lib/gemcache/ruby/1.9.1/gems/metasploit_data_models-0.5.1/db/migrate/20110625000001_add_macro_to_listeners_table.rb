class AddMacroToListenersTable < ActiveRecord::Migration

	def self.up
		add_column :listeners, :macro, :text
	end

	def self.down
		remove_column :listeners, :macro
	end

end

