module MetasploitDataModels::ActiveRecordModels::ModuleDetail
  def self.included(base)
    base.class_eval {
      base.table_name = "modules_details"

      has_many :modules_details_authors, :class_name => "Mdm::ModuleDetailAuthor", :dependent => :destroy
      has_many :modules_authors, :through => :modules_details_authors, :class_name => "Mdm::ModuleAuthor", :dependent => :destroy, :source => :module_author

      has_many :modules_details_mixins, :class_name => "Mdm::ModuleDetailMixin", :dependent => :destroy
      has_many :modules_mixins, :through => :modules_details_mixins, :class_name => "Mdm::ModuleMixin", :dependent => :destroy, :source => :module_mixin

      has_many :modules_details_targets, :class_name => "Mdm::ModuleDetailTarget", :dependent => :destroy
      has_many :modules_targets, :through => :modules_details_targets, :class_name => "Mdm::ModuleTarget", :dependent => :destroy, :source => :module_target

      has_many :modules_details_actions, :class_name => "Mdm::ModuleDetailAction", :dependent => :destroy
      has_many :modules_actions, :through => :modules_details_actions, :class_name => "Mdm::ModuleAction", :dependent => :destroy,  :source => :module_action

      has_many :modules_details_refs, :class_name => "Mdm::ModuleDetailRef", :dependent => :destroy
      has_many :modules_refs, :through => :modules_details_refs, :class_name => "Mdm::ModuleRef", :dependent => :destroy,  :source => :module_ref

      has_many :modules_details_archs, :class_name => "Mdm::ModuleDetailArch", :dependent => :destroy
      has_many :modules_archs, :through => :modules_details_archs, :class_name => "Mdm::ModuleArch", :dependent => :destroy, :source => :module_arch

      has_many :modules_details_platforms, :class_name => "Mdm::ModuleDetailPlatform", :dependent => :destroy
      has_many :modules_platforms, :through => :modules_details_platforms, :class_name => "Mdm::ModulePlatform", :dependent => :destroy,  :source => :module_platform

      validates_associated :modules_refs

      after_update :save_refs

      private

      def save_refs
        modules_refs.each { |ref| ref.save(:validate => false) }
      end
    }
  end
end
