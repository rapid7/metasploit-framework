module MetasploitDataModels::ActiveRecordModels::HostTag
  def self.included(base)
    base.class_eval {
      base.table_name = "hosts_tags"
      belongs_to :host, :class_name => "Mdm::Host"
      belongs_to :tag, :class_name => "Mdm::Tag"
    }
  end
end

