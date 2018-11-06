class CreateTables < ActiveRecord::Migration

	def self.up
		
		create_table :hosts do |t|
			t.timestamp :created
			t.string    :address, :limit => 16 # unique
			t.string    :address6
			t.string    :mac
			t.string    :comm
			t.string    :name
			t.string    :state
			t.string    :info, :limit => 1024
			t.string    :os_name
			t.string    :os_flavor
			t.string    :os_sp
			t.string    :os_lang
			t.string    :arch
		end
		
		add_index :hosts, :address, :unique => true
		
		create_table :clients do |t|
			t.integer   :host_id
			t.timestamp :created
			t.string    :ua_string, :limit => 1024, :null => false
			t.string    :ua_name, :limit => 64
			t.string    :ua_ver, :limit => 32
		end
		
		create_table :services do |t|
			t.integer   :host_id
			t.timestamp :created
			t.integer   :port, :null => false
			t.string    :proto, :limit => 16, :null => false
			t.string    :state
			t.string    :name
			t.string    :info, :limit => 1024
		end
		
		create_table :vulns do |t|
			t.integer   :host_id
			t.integer   :service_id
			t.timestamp :created
			t.string    :name
			t.text      :data
		end
		
		create_table :refs do |t|
			t.integer   :ref_id
			t.timestamp :created
			t.string    :name, :limit => 512
		end
		
		create_table :vulns_refs, :id => false do |t|
			t.integer   :ref_id
			t.integer   :vuln_id
		end
		
		create_table :notes do |t|
			t.integer   :host_id
			t.timestamp :created
			t.string    :ntype, :limit => 512
			t.text      :data
		end
		
	end
	
	def self.down
		drop_table :hosts
		drop_table :clients
		drop_table :services
		drop_table :vulns
		drop_table :refs
		drop_table :vulns_refs
		drop_table :notes
	end

end
