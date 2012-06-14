module MetasploitDataModels::ActiveRecordModels::ModuleArch
  def self.included(base)
    base.class_eval{
      base.table_name = "modules_archs"
      has_many :modules_details_archs, :class_name => "Mdm::ModuleDetailArch"
      has_many :modules_details, :through => :modules_details_archs, :class_name => "Mdm::ModuleArch", :source => :module_detail
      validate :name, :presence => true, :uniqueness => true
    }
  end
end
