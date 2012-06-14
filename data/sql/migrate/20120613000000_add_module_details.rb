class AddModuleDetails < ActiveRecord::Migration

	def self.up
	
		create_table :modules_details do |t|
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

		add_index :modules_details, :refname
		add_index :modules_details, :name

		create_table :modules_authors do |t|
			t.text :name
			t.text :email
		end
		create_table :modules_details_authors, :id => false do |t|
			t.integer :module_detail_id
			t.integer :module_author_id
		end

		create_table :modules_mixins do |t|
			t.text :name
		end
		create_table :modules_details_mixins, :id => false do |t|
			t.integer :module_detail_id
			t.integer :module_mixin_id
		end


		create_table :modules_targets do |t|
			t.integer :index
			t.text :name
		end
		create_table :modules_details_targets, :id => false do |t|
			t.integer :module_detail_id
			t.integer :module_target_id
		end


		create_table :modules_actions do |t|
			t.text :name
		end
		create_table :modules_details_actions, :id => false do |t|
			t.integer :module_detail_id
			t.integer :module_action_id
		end


		create_table :modules_refs do |t|
			t.text :name
		end
		create_table :modules_details_refs, :id => false do |t|
			t.integer :module_detail_id
			t.integer :module_ref_id
		end
		add_index :modules_refs, :name

		create_table :modules_archs do |t|
			t.text :name
		end
		create_table :modules_details_archs, :id => false do |t|
			t.integer :module_detail_id
			t.integer :module_arch_id
		end


		create_table :modules_platforms do |t|
			t.text :name
		end
		create_table :modules_details_platforms, :id => false do |t|
			t.integer :module_detail_id
			t.integer :module_platform_id
		end

	end

	def self.down
		remove_index :modules_details, :refname
		remove_index :modules_details, :name
		remove_index :modules_refs, :name

		drop_table	:modules_details
		drop_table	:modules_authors
		drop_table	:modules_details_authors
		drop_table	:modules_mixins
		drop_table	:modules_details_mixins
		drop_table	:modules_targets
		drop_table	:modules_details_targets
		drop_table	:modules_actions
		drop_table	:modules_details_actions
		drop_table	:modules_refs
		drop_table	:modules_details_refs
		drop_table	:modules_archs
		drop_table	:modules_details_archs
		drop_table	:modules_platforms
		drop_table	:modules_details_platforms
	end
end
