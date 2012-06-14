class AddModuleDetails < ActiveRecord::Migration

	def self.up
	
		create_table :module_details do |t|
			t.timestamp :mtime             # disk modified time
			t.text      :file              # location on disk
			t.string    :type              # exploit, auxiliary, post, etc
			t.text      :refname           # module path (no type)
			t.text      :name              # module title
			t.integer   :rank              # exploit rank
			t.text      :description       #
			t.string	:license           # MSF_LICENSE
			t.boolean	:privileged        # true or false
			t.timestamp :disclosure_date   # Mar 10 2004
			t.integer	:default_target    # 0
			t.text		:default_action    # "scan"
			t.string	:stance            # "passive"
		end

		add_index :module_details, :refname
		add_index :module_details, :name

		create_table :module_authors do |t|
			t.text :name
			t.text :email
		end
		create_table :module_details_authors, :id => false do |t|
			t.integer :module_detail_id
			t.integer :module_author_id
		end

		create_table :module_mixins do |t|
			t.text :name
		end
		create_table :module_details_mixins, :id => false do |t|
			t.integer :module_detail_id
			t.integer :module_mixin_id
		end


		create_table :module_targets do |t|
			t.integer :index
			t.text :name
		end
		create_table :module_details_targets, :id => false do |t|
			t.integer :module_detail_id
			t.integer :module_target_id
		end


		create_table :module_actions do |t|
			t.text :name
		end
		create_table :module_details_actions, :id => false do |t|
			t.integer :module_detail_id
			t.integer :module_action_id
		end


		create_table :module_refs do |t|
			t.text :name
		end
		create_table :module_details_refs, :id => false do |t|
			t.integer :module_detail_id
			t.integer :module_ref_id
		end
		add_index :module_refs, :name

		create_table :module_archs do |t|
			t.text :name
		end
		create_table :module_details_archs, :id => false do |t|
			t.integer :module_detail_id
			t.integer :module_arch_id
		end


		create_table :module_platforms do |t|
			t.text :name
		end
		create_table :module_details_platforms, :id => false do |t|
			t.integer :module_detail_id
			t.integer :module_platform_id
		end

	end

	def self.down
		remove_index :module_details, :refname
		remove_index :module_details, :name
		remove_index :module_refs, :name

		drop_table	:module_details
		drop_table	:module_authors
		drop_table	:module_details_authors
		drop_table	:module_mixins
		drop_table	:module_details_mixins
		drop_table	:module_targets
		drop_table	:module_details_targets
		drop_table	:module_actions
		drop_table	:module_details_actions
		drop_table	:module_refs
		drop_table	:module_details_refs
		drop_table	:module_archs
		drop_table	:module_details_archs
		drop_table	:module_platforms
		drop_table	:module_details_platforms
	end
end
