# Changes `module_refs.module_detail_id` to `module_refs.detail_id` so that foreign key matches the conventional
# name when `Mdm::ModuleDetail` became {Mdm::Module::Detail}.
class ChangeForeignKeyInModuleRefs < ActiveRecord::Migration
  #
  # CONSTANTS
  #

  NEW_COLUMN_NAME= :detail_id
  OLD_COLUMN_NAME = :module_detail_id
  TABLE_NAME = :module_refs

  # Renames `module_refs.detail_id` to `module_refs.module_detail_id`.
  #
  # @return [void]
  def down
    rename_column TABLE_NAME, NEW_COLUMN_NAME, OLD_COLUMN_NAME
  end

  # Rename `module_refs.module_detail_id` to `module_refs.detail_id`
  #
  # @return [void]
  def up
    rename_column TABLE_NAME, OLD_COLUMN_NAME, NEW_COLUMN_NAME
  end
end
