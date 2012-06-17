module MetasploitDataModels::ActiveRecordModels::ModuleDetail
  def self.included(base)
    base.class_eval {
      base.table_name = "module_details"

      has_many :authors,   :class_name => "Mdm::ModuleAuthor",   :dependent => :destroy, :source => :module_author
      has_many :mixins,    :class_name => "Mdm::ModuleMixin",    :dependent => :destroy, :source => :module_mixin
      has_many :targets,   :class_name => "Mdm::ModuleTarget",   :dependent => :destroy, :source => :module_target   
      has_many :actions,   :class_name => "Mdm::ModuleAction",   :dependent => :destroy, :source => :module_action
      has_many :refs,      :class_name => "Mdm::ModuleRef",      :dependent => :destroy, :source => :module_ref 
      has_many :archs,     :class_name => "Mdm::ModuleArch",     :dependent => :destroy, :source => :module_arch
      has_many :platforms, :class_name => "Mdm::ModulePlatform", :dependent => :destroy, :source => :module_platform

      validate :refname,   :presence => true

      validates_associated :authors
      validates_associated :mixins
      validates_associated :targets
      validates_associated :actions
      validates_associated :archs
      validates_associated :platforms
      validates_associated :refs

      # Add a new sub-object without creating duplicates
      def add(obj,vals)
        raise RuntimeError, "Invalid object type" unless Mdm.const_defined?("Module#{obj.to_s.capitalize}")
        cls = Mdm.const_get("Module#{obj.to_s.capitalize}")
        tgt = cls.find(:first, :conditions => vals)
        if not tgt
          tgt = cls.create(vals)
        end
	tgt
     end

    }
  end
end
