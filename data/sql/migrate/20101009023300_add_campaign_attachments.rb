

class AddCampaignAttachments < ActiveRecord::Migration

	def self.up
		add_column :attachments, :campaign_id, :integer
	end

	def self.down
		remove_column :attachments, :campaign_id
	end

end


