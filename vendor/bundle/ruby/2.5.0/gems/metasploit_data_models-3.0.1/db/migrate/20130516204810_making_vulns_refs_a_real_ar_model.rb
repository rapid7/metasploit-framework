class MakingVulnsRefsARealArModel < ActiveRecord::Migration
  def change
    add_column :vulns_refs, :id, :primary_key
  end
end