class AddLastSeenToSessions < ActiveRecord::Migration
	def self.up
		add_column :sessions, :last_seen, :timestamp
	end
	def self.down
		remove_column :sessions, :last_seen
	end
end
