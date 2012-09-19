module MetasploitDataModels::ActiveRecordModels::CredFile
  def self.included(base)
    base.class_eval{

      belongs_to :workspace, :class_name => "Mdm::Workspace"
    }
  end
end
