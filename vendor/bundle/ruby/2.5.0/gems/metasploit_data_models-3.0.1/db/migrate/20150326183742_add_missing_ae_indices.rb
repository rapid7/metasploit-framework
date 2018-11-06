class AddMissingAeIndices < ActiveRecord::Migration
  def up
    add_index :automatic_exploitation_match_results, :match_id
    add_index :automatic_exploitation_match_results, :run_id

    add_index :automatic_exploitation_runs, :match_set_id
    add_index :automatic_exploitation_runs, :user_id
    add_index :automatic_exploitation_runs, :workspace_id
  end

  def down
  end
end
