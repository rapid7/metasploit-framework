class RemoveCampaignIdFromClients < ActiveRecord::Migration
  def up
    remove_column :clients, :campaign_id
  end

  def down
    remove_column :clients, :campaign_id, :integer
  end
end
