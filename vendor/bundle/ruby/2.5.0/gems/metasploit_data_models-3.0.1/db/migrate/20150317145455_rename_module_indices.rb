class RenameModuleIndices < ActiveRecord::Migration
  def change
    # This migration will only need to be run if the indices were originally
    # generated before Rails 4. Fresh builds can safely skip this.
    return if ActiveRecord::Base.connection.indexes(:module_actions).first.name != 'index_module_actions_on_module_detail_id'

    rename_index :module_actions,
                 'index_module_actions_on_module_detail_id',
                 'index_module_actions_on_detail_id'
    rename_index :module_archs,
                 'index_module_archs_on_module_detail_id',
                 'index_module_archs_on_detail_id'
    rename_index :module_authors,
                 'index_module_authors_on_module_detail_id',
                 'index_module_authors_on_detail_id'
    rename_index :module_mixins,
                 'index_module_mixins_on_module_detail_id',
                 'index_module_mixins_on_detail_id'
    rename_index :module_platforms,
                 'index_module_platforms_on_module_detail_id',
                 'index_module_platforms_on_detail_id'
    rename_index :module_refs,
                 'index_module_refs_on_module_detail_id',
                 'index_module_refs_on_detail_id'
    rename_index :module_targets,
                 'index_module_targets_on_module_detail_id',
                 'index_module_targets_on_detail_id'
  end
end
