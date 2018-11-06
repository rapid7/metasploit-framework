class CreateModuleRuns < ActiveRecord::Migration
  def change
    create_table :module_runs do |t|
      t.datetime :attempted_at
      t.text :fail_detail
      t.string :fail_reason
      t.text :module_fullname
      t.integer :port
      t.string :proto
      t.integer :session_id
      t.string :status
      t.integer :trackable_id
      t.string :trackable_type
      t.integer :user_id
      t.string :username

      t.timestamps null: false
    end

    add_index :module_runs, :session_id
    add_index :module_runs, :user_id
  end
end
