module MetasploitDataModels::ActiveRecordModels::Client
  def self.included(base)
    base.class_eval {
      belongs_to :host, :class_name => "Mdm::Host"
      belongs_to :campaign, :class_name => "Campaign"
    }
  end
end
