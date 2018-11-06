class MakingHostTagsARealArModel < ActiveRecord::Migration
  def change
    add_column :hosts_tags, :id, :primary_key
  end

end
