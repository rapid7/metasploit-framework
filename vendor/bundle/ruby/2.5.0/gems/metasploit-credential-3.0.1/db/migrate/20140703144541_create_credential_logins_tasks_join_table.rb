class CreateCredentialLoginsTasksJoinTable < ActiveRecord::Migration
  def change
    create_table :credential_logins_tasks, :force => true, :id => false do |t|
      t.integer :login_id
      t.integer :task_id
    end
  end
end
