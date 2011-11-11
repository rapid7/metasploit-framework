
class AddCampaignsAndTemplates < ActiveRecord::Migration

	def self.up
		create_table :campaigns do |t|
			t.integer   :workspace_id, :null => false
			t.string    :name, :limit => 512
			# Serialized, stores SMTP/other protocol config options etc.
			t.text      :prefs
			t.integer   :status, :default => 0
			t.timestamp :started_at
			t.timestamps
		end

		create_table :email_templates do |t|
			t.string  :name,    :limit => 512
			t.string  :subject, :limit => 1024
			t.text    :body
			t.integer :parent_id
			t.integer :campaign_id
		end
		create_table :attachments do |t|
			t.string  :name,    :limit => 512
			t.binary  :data
			t.string  :content_type, :limit => 512
			t.boolean :inline,  :null => false, :default => true
			t.boolean :zip,     :null => false, :default => false
		end
		create_table :attachments_email_templates, :id => false do |t|
			t.integer :attachment_id
			t.integer :email_template_id
		end

		create_table :email_addresses do |t|
			t.integer :campaign_id, :null => false
			t.string  :first_name,  :limit => 512
			t.string  :last_name,   :limit => 512
			t.string  :address,     :limit => 512
			t.boolean :sent,        :null => false, :default => false
			t.timestamp :clicked_at
		end

		create_table :web_templates do |t|
			t.string  :name,    :limit => 512
			t.string  :title,   :limit => 512
			t.string  :body,    :limit => 524288
			t.integer :campaign_id
		end
	end

	def self.down
		drop_table :campaigns
		drop_table :email_templates
		drop_table :attachments
		drop_table :attachments_email_templates
		drop_table :email_addresses
		drop_table :web_templates
	end

end

