class AddCredsTable < ActiveRecord::Migration
	def self.up
		create_table :creds do |t|
			t.integer   :service_id, :null => false
			t.timestamps 
			t.string    :user, :limit => 2048
			t.string    :pass, :limit => 4096
			t.boolean   :active, :default => true
			t.string    :proof, :limit => 4096
			t.string    :ptype, :limit => 16 
			t.integer   :source_id
			t.string    :source_type
		end
	end
	def self.down
		drop_table :creds
	end
end

