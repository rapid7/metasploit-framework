module MetasploitDataModels::ActiveRecordModels::ExploitedHost
  def self.included(base)
    base.class_eval{
      belongs_to :host, :class_name => "Mdm::Host"
      belongs_to :service, :class_name => "Mdm::Service"
      belongs_to :workspace, :class_name => "Mdm::Workspace"
    }
  end
end
