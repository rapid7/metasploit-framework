# Changes `module_actions.module_detail_id` to `module_actions.detail_id` so that foreign key matches the conventional
# name when `Mdm::ModuleDetail` became {Mdm::Module::Detail}.
class ChangeForeignKeyInModuleActions < ActiveRecord::Migration
  #
  # CONSTANTS
  #

  NEW_COLUMN_NAME= :detail_id
  OLD_COLUMN_NAME = :module_detail_id
  TABLE_NAME = :module_actions

  # Renames `module_actions.detail_id` to `module_actions.module_detail_id`.
  #
  # @return [void]
  def down
    rename_column TABLE_NAME, NEW_COLUMN_NAME, OLD_COLUMN_NAME
  end

  # Rename `module_actions.module_detail_id` to `module_actions.detail_id`
  #
  # @return [void]
  def up
    rename_column TABLE_NAME, OLD_COLUMN_NAME, NEW_COLUMN_NAME
  end
end
