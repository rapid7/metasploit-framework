module MetasploitDataModels::ActiveRecordModels::ModuleAuthor
  def self.included(base)
    base.class_eval{
      base.table_name = "modules_authors"
      has_many :modules_details_authors, :class_name => "Mdm::ModuleDetailAuthor"
      has_many :modules_details, :through => :modules_details_authors, :class_name => "Mdm::ModuleDetail", :source => :module_detail
    }
  end
end
