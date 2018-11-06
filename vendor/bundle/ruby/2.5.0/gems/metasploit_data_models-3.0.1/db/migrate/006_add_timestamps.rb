
# Adds 'created_at' and 'updated_at' columns to every primary table.
#
class AddTimestamps < ActiveRecord::Migration

	@@TABLES_NEEDING_RENAME = [:clients, :hosts, :notes, :refs, :services, :vulns, :wmap_requests]
	@@TABLES_NEEDING_CREATED_AT = [:wmap_targets]
	@@TABLES_NEEDING_UPDATED_AT = [:clients, :events, :hosts, :notes, :refs, :services, :vulns, :wmap_requests, :wmap_targets]

	def self.up
		@@TABLES_NEEDING_RENAME.each { |t| rename_column t, :created, :created_at }
		
		@@TABLES_NEEDING_CREATED_AT.each { |t| add_column t, :created_at, :datetime }

		@@TABLES_NEEDING_UPDATED_AT.each { |t| add_column t, :updated_at, :datetime }
	end

	def self.down
		@@TABLES_NEEDING_RENAME.each { |t| rename_column t, :created_at, :created }
		
		@@TABLES_NEEDING_CREATED_AT.each { |t| remove_column t, :created_at }

		@@TABLES_NEEDING_UPDATED_AT.each { |t| remove_column t, :updated_at }
	end
end

