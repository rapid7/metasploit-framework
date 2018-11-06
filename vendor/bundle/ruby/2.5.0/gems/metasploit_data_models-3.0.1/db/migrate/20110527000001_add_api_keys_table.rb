class AddApiKeysTable < ActiveRecord::Migration
	def self.up
		create_table :api_keys do |t|
			t.text :token
			t.timestamps null: false
		end
	end
	def self.down
		drop_table :api_keys
	end
end

