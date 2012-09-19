class CreateUsers < ActiveRecord::Migration
  def self.up
    create_table :users do |t|
      t.string :name, :state, :access_state
    end
  end
  
  def self.down
    drop_table :users
  end
end
