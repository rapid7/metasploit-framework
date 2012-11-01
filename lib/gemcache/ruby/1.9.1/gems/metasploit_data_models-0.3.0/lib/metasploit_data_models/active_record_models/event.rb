module MetasploitDataModels::ActiveRecordModels::Event
  def self.included(base)
    base.class_eval{
      belongs_to :workspace, :class_name => "Mdm::Workspace"
      belongs_to :host

      serialize :info, ::MetasploitDataModels::Base64Serializer.new

      scope :flagged, where(:critical => true, :seen => false)
      scope :module_run, where(:name => 'module_run')

      validates_presence_of :name
    }
  end
end

