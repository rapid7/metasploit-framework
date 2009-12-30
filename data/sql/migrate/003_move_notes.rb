class MoveNotes < ActiveRecord::Migration
	def self.up
		# Remove the host requirement.  We'll add the column back in below.
		remove_column :notes, :host_id
		change_table :notes do |t|
			t.integer :workspace_id, :null => false, :default => 1
			t.integer :service_id
			t.integer :host_id
		end
	end

	def self.down
		remove_column :notes, :workspace_id
		remove_column :notes, :service_id
		change_table :notes do |t|
			t.integer :host_id, :null => false
		end
	end
end

