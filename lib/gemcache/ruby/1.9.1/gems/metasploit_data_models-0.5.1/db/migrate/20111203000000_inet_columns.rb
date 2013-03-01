class InetColumns < ActiveRecord::Migration

  def self.up
    change_column :hosts, :address, 'INET using address::INET'
    remove_column :hosts, :address6
  end

  def self.down
    change_column :hosts, :address, :text
    add_column :hosts, :address6, :text
  end

end
