class AddInitialIndexes < ActiveRecord::Migration
	def self.up


		add_index :hosts, :address
		add_index :hosts, :address6
		add_index :hosts, :name
		add_index :hosts, :state
		add_index :hosts, :os_name
		add_index :hosts, :os_flavor
		add_index :hosts, :purpose

		# Removed (conditionally dropped in the next migration)
		# add_index :hosts, :comments

		add_index :services, :port
		add_index :services, :proto
		add_index :services, :state
		add_index :services, :name

		# Removed (conditionally dropped in the next migration)
		# add_index :services, :info

		add_index :notes, :ntype

		add_index :vulns, :name

		# Removed (conditionally dropped in the next migration)
		# add_index :vulns, :info

		add_index :refs, :name

		add_index :web_sites, :vhost
		add_index :web_sites, :comments
		add_index :web_sites, :options

		add_index :web_pages, :path
		add_index :web_pages, :query

		add_index :web_forms, :path

		add_index :web_vulns, :path
		add_index :web_vulns, :method
		add_index :web_vulns, :name
	end

	def self.down

		remove_index :hosts, :address
		remove_index :hosts, :address6
		remove_index :hosts, :name
		remove_index :hosts, :state
		remove_index :hosts, :os_name
		remove_index :hosts, :os_flavor
		remove_index :hosts, :purpose
		remove_index :hosts, :comments

		remove_index :services, :port
		remove_index :services, :proto
		remove_index :services, :state
		remove_index :services, :name
		remove_index :services, :info

		remove_index :notes, :ntype

		remove_index :vulns, :name
		remove_index :vulns, :info

		remove_index :refs, :name

		remove_index :web_sites, :vhost
		remove_index :web_sites, :comments
		remove_index :web_sites, :options

		remove_index :web_pages, :path
		remove_index :web_pages, :query

		remove_index :web_forms, :path

		remove_index :web_vulns, :path
		remove_index :web_vulns, :method
		remove_index :web_vulns, :name
	end
end

