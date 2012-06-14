module MetasploitDataModels::ActiveRecordModels::ModuleDetail
  def self.included(base)
    base.class_eval {

      has_many :module_authors, :through => :modules_details_authors, :class_name => "Mdm::ModuleAuthor", :dependent => :destroy
      has_many :module_mixins, :through => :modules_details_mixins, :class_name => "Mdm::ModuleMixin", :dependent => :destroy
      has_many :module_targets, :through => :modules_details_targets, :class_name => "Mdm::ModuleTarget", :dependent => :destroy
      has_many :module_actions, :through => :modules_details_actions, :class_name => "Mdm::ModuleAction", :dependent => :destroy
      has_many :module_refs, :through => :modules_details_refs, :class_name => "Mdm::ModuleRef", :dependent => :destroy
      has_many :module_archs, :through => :modules_details_archs, :class_name => "Mdm::ModuleArch", :dependent => :destroy
      has_many :module_platforms, :through => :modules_details_platforms, :class_name => "Mdm::ModulePlatform", :dependent => :destroy

      validates_associated :module_refs

      after_update :save_refs

      private

      def save_refs
        module_refs.each { |ref| ref.save(:validate => false) }
      end
    }
  end
end
