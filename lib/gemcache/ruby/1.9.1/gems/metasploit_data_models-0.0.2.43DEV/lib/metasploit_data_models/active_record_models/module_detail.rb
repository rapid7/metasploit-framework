module MetasploitDataModels::ActiveRecordModels::ModuleDetail
  def self.included(base)
    base.class_eval {
      base.table_name = "modules_details"

      has_many :modules_details_authors, :class_name => "Mdm::ModuleDetailAuthor", :dependent => :destroy
      has_many :authors, :through => :modules_details_authors, :class_name => "Mdm::ModuleAuthor", :dependent => :destroy, :source => :module_author

      has_many :modules_details_mixins, :class_name => "Mdm::ModuleDetailMixin", :dependent => :destroy
      has_many :mixins, :through => :modules_details_mixins, :class_name => "Mdm::ModuleMixin", :dependent => :destroy, :source => :module_mixin

      has_many :modules_details_targets, :class_name => "Mdm::ModuleDetailTarget", :dependent => :destroy
      has_many :targets, :through => :modules_details_targets, :class_name => "Mdm::ModuleTarget", :dependent => :destroy, :source => :module_target

      has_many :modules_details_actions, :class_name => "Mdm::ModuleDetailAction", :dependent => :destroy
      has_many :actions, :through => :modules_details_actions, :class_name => "Mdm::ModuleAction", :dependent => :destroy,  :source => :module_action

      has_many :modules_details_refs, :class_name => "Mdm::ModuleDetailRef"
      has_many :refs, :through => :modules_details_refs, :class_name => "Mdm::ModuleRef", :dependent => :destroy,  :source => :module_ref

      has_many :modules_details_archs, :class_name => "Mdm::ModuleDetailArch", :dependent => :destroy
      has_many :archs, :through => :modules_details_archs, :class_name => "Mdm::ModuleArch", :dependent => :destroy, :source => :module_arch

      has_many :modules_details_platforms, :class_name => "Mdm::ModuleDetailPlatform", :dependent => :destroy
      has_many :platforms, :through => :modules_details_platforms, :class_name => "Mdm::ModulePlatform", :dependent => :destroy,  :source => :module_platform


      validate :refname, :presence => true, :uniqueness => true

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

        cls_lnk  = Mdm.const_get("ModuleDetail#{obj.to_s.capitalize}")
        criteria = { "module_#{obj.to_s.downcase}_id".to_sym => tgt.id, "module_detail_id" => self.id }
        res = cls_lnk.find(:first, :conditions => criteria)
        if not res
          res = cls_lnk.create(criteria)
        end
		res
     end

    }
  end
end
