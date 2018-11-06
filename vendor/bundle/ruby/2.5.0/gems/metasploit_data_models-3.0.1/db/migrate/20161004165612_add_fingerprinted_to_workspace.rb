class AddFingerprintedToWorkspace < ActiveRecord::Migration
  def change
    add_column :workspaces, :import_fingerprint, :boolean, default: false
  end
end
