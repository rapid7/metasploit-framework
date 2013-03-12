# Probably temporary, a spot to stash module names and their associated refs
# Don't count on it being populated at any given moment.
class AddModRefTable < ActiveRecord::Migration

	def self.up
		create_table :mod_refs do |t|
			t.string :module, :limit => 1024
			t.string :mtype, :limit => 128
			t.text :ref
		end
	end

	def self.down
		drop_table :mod_refs
	end

end
