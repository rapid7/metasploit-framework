class AddRoutesTable < ActiveRecord::Migration

	def self.up
		create_table :routes do |t|
			t.integer :session_id
			t.string  :subnet
			t.string  :netmask
		end

		remove_column :sessions, :routes
	end

	def self.down
		drop_table :routes

		add_column :sessions, :routes, :string
	end
end
