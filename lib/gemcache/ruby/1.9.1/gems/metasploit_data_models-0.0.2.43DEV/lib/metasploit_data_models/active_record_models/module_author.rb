module MetasploitDataModels::ActiveRecordModels::ModuleAuthor
  def self.included(base)
    base.class_eval{
      has_many :module_details_authors, :class_name => "Mdm::ModuleDetailAuthor"
      has_many :module_details, :through => :module_details_authors, :class_name => "Mdm::ModuleDetail"
    }
  end
end
