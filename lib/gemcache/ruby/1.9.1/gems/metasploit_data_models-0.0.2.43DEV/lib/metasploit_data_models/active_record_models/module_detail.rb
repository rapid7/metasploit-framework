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

      def add_author(name, email=nil)
        if email
          self.authors.find_or_create_by_name_and_email(name, email)
        else
          self.authors.find_or_create_by_name(name)
        end
      end

      def add_mixin(name)
        self.mixins.find_or_create_by_name(name)
      end

      def add_target(idx, name)
        obj = self.targets.find_or_create_by_index(idx)
        obj.name = name
        obj.save if obj.changed?
        obj
      end

      def add_action(name)
        self.actions.find_or_create_by_name(name)
      end

      def add_ref(name)
        self.refs.find_or_create_by_name(name)
      end

      def add_arch(name)
        self.archs.find_or_create_by_name(name)
      end

      def add_platform(name)
        self.platforms.find_or_create_by_name(name)
      end
    }
  end
end
