class AddExploitedTable < ActiveRecord::Migration
	def self.up
		create_table :exploited_hosts do |t|
			t.integer   :host_id, :null => false
			t.integer   :service_id
			t.string    :session_uuid, :limit => 8
			t.string    :name, :limit => 2048
			t.string    :payload, :limit => 2048
			t.timestamps 
		end
	end
	def self.down
		drop_table :exploited_hosts
	end
end

