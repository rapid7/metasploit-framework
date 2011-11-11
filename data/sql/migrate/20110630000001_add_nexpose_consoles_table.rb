class AddNexposeConsolesTable < ActiveRecord::Migration
	def self.up
		create_table :nexpose_consoles do |t|
			t.timestamps
			t.boolean :enabled, :default => true
			t.text :owner
			t.text :address
			t.integer :port, :default => 3780
			t.text :username
			t.text :password
			t.text :status
			t.text :version
			t.text :cert
			t.binary :cached_sites
		end
	end
	def self.down
		drop_table :nexpose_consoles
	end
end

