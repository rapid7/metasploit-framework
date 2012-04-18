module MetasploitDataModels::ActiveRecordModels::Listener
  def self.included(base)
    base.class_eval{

      belongs_to :workspace, :class_name => "Mdm::Workspace"
      belongs_to :task, :class_name => "Mdm::Task"

      serialize :options, ::MetasploitDataModels::Base64Serializer.new
      validates :address, :presence => true, :ip_format => true
      validates :port, :presence => true
    }
  end
end

