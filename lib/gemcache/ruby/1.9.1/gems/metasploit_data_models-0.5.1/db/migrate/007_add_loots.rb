class AddLoots < ActiveRecord::Migration

	def self.up
		create_table :loots do |t|
			t.integer   :workspace_id, :null => false, :default => 1
			t.integer   :host_id
			t.integer   :service_id
			t.string    :ltype, :limit => 512
			t.string    :path, :limit  => 1024
			t.text      :data
			t.timestamps
		end
	end

	def self.down
		drop_table :loots
	end

end

