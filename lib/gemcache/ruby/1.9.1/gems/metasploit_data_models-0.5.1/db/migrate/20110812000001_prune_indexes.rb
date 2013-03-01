class PruneIndexes < ActiveRecord::Migration
	def self.up

		if indexes(:hosts).map{|x| x.columns }.flatten.include?("comments")
			remove_index :hosts, :comments
		end

		if indexes(:services).map{|x| x.columns }.flatten.include?("info")
			remove_index :services, :info
		end

		if indexes(:vulns).map{|x| x.columns }.flatten.include?("info")
			remove_index :vulns, :info
		end
	end

	def self.down
		add_index :hosts, :comments
		add_index :services, :info
		add_index :vulns, :info
	end
end

