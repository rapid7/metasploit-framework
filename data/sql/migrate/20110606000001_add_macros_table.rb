class AddMacrosTable < ActiveRecord::Migration
	def self.up
		create_table :macros do |t|
			t.timestamps
			t.text :owner
			t.text :name
			t.text :description
			t.binary :actions
			t.binary :prefs			
		end
	end
	def self.down
		drop_table :macros
	end
end

