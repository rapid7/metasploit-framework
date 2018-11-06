# Changes `module_archs.module_detail_id` to `module_archs.detail_id` so that foreign key matches the conventional
# name when `Mdm::ModuleDetail` became {Mdm::Module::Detail}.
class ChangeForeignKeyInModuleArchs < ActiveRecord::Migration
  #
  # CONSTANTS
  #

  NEW_COLUMN_NAME= :detail_id
  OLD_COLUMN_NAME = :module_detail_id
  TABLE_NAME = :module_archs

  # Renames `module_archs.detail_id` to `module_archs.module_detail_id`.
  #
  # @return [void]
  def down
    rename_column TABLE_NAME, NEW_COLUMN_NAME, OLD_COLUMN_NAME
  end

  # Rename `module_archs.module_detail_id` to `module_archs.detail_id`
  #
  # @return [void]
  def up
    rename_column TABLE_NAME, OLD_COLUMN_NAME, NEW_COLUMN_NAME
  end
end
