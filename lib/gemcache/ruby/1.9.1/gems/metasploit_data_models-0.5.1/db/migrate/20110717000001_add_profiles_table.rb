class AddProfilesTable < ActiveRecord::Migration
	def self.up
		create_table :profiles do |t|
			t.timestamps
			t.boolean :active, :default => true
			t.text :name
			t.text :owner
			t.binary :settings
		end
	end
	def self.down
		drop_table :profiles
	end
end

