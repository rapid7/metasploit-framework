module MetasploitDataModels::ActiveRecordModels::ModuleDetailAuthor
  def self.included(base)
    base.class_eval {
      base.table_name = "modules_details_authors"
      belongs_to :module_detail, :class_name => "Mdm::ModuleDetail"
      belongs_to :module_author, :class_name => "Mdm::ModuleAuthor"
      validate :module_detail, :presence => true
      validate :module_author, :presence => true
    }
  end
end

