class AddModuleDetails < ActiveRecord::Migration

	def self.up
	
		create_table :module_details do |t|
			t.timestamp :mtime             # disk modified time
			t.text      :file              # location on disk
			t.string    :mtype             # exploit, auxiliary, post, etc
			t.text      :refname           # module path (no type)
			t.text      :fullname          # module path with type
			t.text      :name              # module title
			t.integer   :rank              # exploit rank
			t.text      :description       #
			t.string	:license           # MSF_LICENSE
			t.boolean	:privileged        # true or false
			t.timestamp :disclosure_date   # Mar 10 2004
			t.integer	:default_target    # 0
			t.text		:default_action    # "scan"
			t.string	:stance            # "passive"
			t.boolean	:ready             # true/false
		end

		add_index :module_details, :refname
		add_index :module_details, :name
		add_index :module_details, :description
		add_index :module_details, :mtype

		create_table :module_authors do |t|
			t.integer :module_detail_id
			t.text :name
			t.text :email
		end
		add_index :module_authors, :module_detail_id

		create_table :module_mixins do |t|
			t.integer :module_detail_id
			t.text :name
		end
		add_index :module_mixins, :module_detail_id

		create_table :module_targets do |t|
			t.integer :module_detail_id
			t.integer :index
			t.text :name
		end
		add_index :module_targets, :module_detail_id

		create_table :module_actions do |t|
			t.integer :module_detail_id
			t.text :name
		end
		add_index :module_actions, :module_detail_id

		create_table :module_refs do |t|
			t.integer :module_detail_id
			t.text :name
		end
		add_index :module_refs, :module_detail_id
		add_index :module_refs, :name

		create_table :module_archs do |t|
			t.integer :module_detail_id
			t.text :name
		end
		add_index :module_archs, :module_detail_id
	
		create_table :module_platforms do |t|
			t.integer :module_detail_id
			t.text :name
		end
		add_index :module_platforms, :module_detail_id

	end

	def self.down
		remove_index :module_details, :refname
		remove_index :module_details, :name
		remove_index :module_details, :description
		remove_index :module_details, :mtype

		remove_index :module_authors, :module_detail_id
		remove_index :module_mixins, :module_detail_id
		remove_index :module_targets, :module_detail_id
		remove_index :module_actions, :module_detail_id
		remove_index :module_refs, :module_detail_id
		remove_index :module_refs, :name
		remove_index :module_archs, :module_detail_id
		remove_index :module_platform, :module_detail_id

		drop_table	:module_details
		drop_table	:module_authors
		drop_table	:module_mixins
		drop_table	:module_targets
		drop_table	:module_actions
		drop_table	:module_refs
		drop_table	:module_archs
		drop_table	:module_platforms

	end
end

=begin

Mdm::Host.find_by_sql("
SELECT
	hosts.id, hosts.address, module_details.mtype AS mtype, module_details.refname AS mname, vulns.name AS vname, refs.name AS vref
FROM
	hosts,vulns,vulns_refs,refs,module_refs,module_details
WHERE
	hosts.id = vulns.host_id AND
	vulns.id = vulns_refs.vuln_id AND
	vulns_refs.ref_id = refs.id AND
	refs.name = module_refs.name AND
	module_refs.module_detail_id = modules_details.id
").map{|x| [x.address, x.mname, x.vname, x.vref ] }


=end
