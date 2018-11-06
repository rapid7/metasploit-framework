class CreateCredentialCoresTasksJoinTable < ActiveRecord::Migration
  def change
    create_table :credential_cores_tasks, :force => true, :id => false do |t|
      t.integer :core_id
      t.integer :task_id
    end
  end
end