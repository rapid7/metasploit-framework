module MetasploitDataModels::ActiveRecordModels::HostDetail
  def self.included(base)
    base.class_eval {
      belongs_to :host, :class_name => "Mdm::Host"
      validates :host_id, :presence => true
    }
  end
end
