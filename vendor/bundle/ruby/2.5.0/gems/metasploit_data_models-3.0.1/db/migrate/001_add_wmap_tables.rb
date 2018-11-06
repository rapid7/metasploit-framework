class AddWmapTables < ActiveRecord::Migration
	def self.up
		create_table :wmap_targets do |t|
			t.string  :host                  # vhost
			t.string  :address, :limit => 16 # unique
			t.string  :address6
			t.integer :port
			t.integer :ssl
			t.integer :selected
		end

		create_table :wmap_requests do |t|
			t.string  :host                  # vhost
			t.string  :address, :limit => 16 # unique
			t.string  :address6
			t.integer :port
			t.integer :ssl
			t.string  :meth, :limit => 32
			t.text    :path
			t.text    :headers
			t.text    :query
			t.text    :body
			t.string  :respcode, :limit => 16
			t.text    :resphead
			t.text    :response
			t.timestamp :created
		end
	end

	def self.down
		drop_table :wmap_targets
		drop_table :wmap_requests
	end
end

