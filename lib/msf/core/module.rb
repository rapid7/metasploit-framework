# -*- coding: binary -*-
require 'msf/core'

module Msf

  autoload :OptionContainer, 'msf/core/option_container'

###
#
# The module base class is responsible for providing the common interface
# that is used to interact with modules at the most basic levels, such as
# by inspecting a given module's attributes (name, description, version,
# authors, etc) and by managing the module's data store.
#
###
class Module
  autoload :Alert, 'msf/core/module/alert'
  autoload :Arch, 'msf/core/module/arch'
  autoload :Auth, 'msf/core/module/auth'
  autoload :Author, 'msf/core/module/author'
  autoload :AuxiliaryAction, 'msf/core/module/auxiliary_action'
  autoload :Compatibility, 'msf/core/module/compatibility'
  autoload :DataStore, 'msf/core/module/data_store'
  autoload :Deprecated, 'msf/core/module/deprecated'
  autoload :Failure, 'msf/core/module/failure'
  autoload :FullName, 'msf/core/module/full_name'
  autoload :HasActions, 'msf/core/module/has_actions'
  autoload :ModuleInfo, 'msf/core/module/module_info'
  autoload :ModuleStore, 'msf/core/module/module_store'
  autoload :Network, 'msf/core/module/network'
  autoload :Options, 'msf/core/module/options'
  autoload :Platform, 'msf/core/module/platform'
  autoload :PlatformList, 'msf/core/module/platform_list'
  autoload :Privileged, 'msf/core/module/privileged'
  autoload :Ranking, 'msf/core/module/ranking'
  autoload :Reference, 'msf/core/module/reference'
  autoload :Search, 'msf/core/module/search'
  autoload :SiteReference, 'msf/core/module/reference'
  autoload :Target, 'msf/core/module/target'
  autoload :Type, 'msf/core/module/type'
  autoload :UI, 'msf/core/module/ui'
  autoload :UUID, 'msf/core/module/uuid'
  autoload :SideEffects, 'msf/core/module/side_effects'
  autoload :Stability, 'msf/core/module/stability'
  autoload :Reliability, 'msf/core/module/reliability'

  include Msf::Module::Alert
  include Msf::Module::Arch
  include Msf::Module::Auth
  include Msf::Module::Author
  include Msf::Module::Compatibility
  include Msf::Module::DataStore
  include Msf::Module::FullName
  include Msf::Module::ModuleInfo
  include Msf::Module::ModuleStore
  include Msf::Module::Network
  include Msf::Module::Options
  include Msf::Module::Privileged
  include Msf::Module::Ranking
  include Msf::Module::Search
  include Msf::Module::Type
  include Msf::Module::UI
  include Msf::Module::UUID
  include Msf::Module::SideEffects
  include Msf::Module::Stability
  include Msf::Module::Reliability

  # The key where a comma-separated list of Ruby module names will live in the
  # datastore, consumed by #replicant to allow clean override of MSF module methods.
  REPLICANT_EXTENSION_DS_KEY = 'ReplicantExtensions'

  # Make include public so we can runtime extend
  public_class_method :include

  class << self
    include Framework::Offspring

    #
    # This attribute holds the non-duplicated copy of the module
    # implementation.  This attribute is used for reloading purposes so that
    # it can be re-duplicated.
    #
    attr_accessor :orig_cls

    #
    # The path from which the module was loaded.
    #
    attr_accessor :file_path
  end

  #
  # Returns the class reference to the framework
  #
  def framework
    self.class.framework
  end

  #
  # Creates an instance of an abstract module using the supplied information
  # hash.
  #
  def initialize(info = {})
    @module_info_copy = info.dup

    self.module_info = info
    generate_uuid

    set_defaults

    # Initialize module compatibility hashes
    init_compat

    # Fixup module fields as needed
    info_fixups

    # Transform some of the fields to arrays as necessary
    self.author = Msf::Author.transform(module_info['Author'])
    self.arch = Rex::Transformer.transform(module_info['Arch'], Array, [ String ], 'Arch')
    self.platform = PlatformList.transform(module_info['Platform'])
    self.references = Rex::Transformer.transform(module_info['References'], Array, [ SiteReference, Reference ], 'Ref')

    # Create and initialize the option container for this module
    self.options = Msf::OptionContainer.new
    self.options.add_options(info['Options'], self.class)
    self.options.add_advanced_options(info['AdvancedOptions'], self.class)
    self.options.add_evasion_options(info['EvasionOptions'], self.class)

    # Create and initialize the data store for this module
    self.datastore = ModuleDataStore.new(self)

    # Import default options into the datastore
    import_defaults

    self.privileged = module_info['Privileged'] || false
    self.license = module_info['License'] || MSF_LICENSE

    # Allow all modules to track their current workspace
    register_advanced_options(
      [
        OptString.new('WORKSPACE', [ false, "Specify the workspace for this module" ]),
        OptBool.new('VERBOSE',     [ false, 'Enable detailed status messages', false ])
      ], Msf::Module)

  end

  #
  # Creates a fresh copy of an instantiated module
  #
  def replicant
    obj = self.clone
    self.instance_variables.each { |k|
      v = instance_variable_get(k)
      v = v.dup rescue v
      obj.instance_variable_set(k, v)
    }

    obj.datastore    = self.datastore.copy
    obj.user_input   = self.user_input
    obj.user_output  = self.user_output
    obj.module_store = self.module_store.clone

    obj.perform_extensions
    obj
  end

  # Extends self with the constant list in the datastore
  # @return [void]
  def perform_extensions
    if datastore[REPLICANT_EXTENSION_DS_KEY].present?
      if datastore[REPLICANT_EXTENSION_DS_KEY].respond_to?(:each)
        datastore[REPLICANT_EXTENSION_DS_KEY].each do |const|
          self.extend(const)
        end
      else
        fail "Invalid settings in datastore at key #{REPLICANT_EXTENSION_DS_KEY}"
      end
    end
  end

  # @param[Constant] One or more Ruby constants
  # @return [void]
  def register_extensions(*rb_modules)
    datastore[REPLICANT_EXTENSION_DS_KEY] = [] unless datastore[REPLICANT_EXTENSION_DS_KEY].present?
    rb_modules.each do |rb_mod|
      datastore[REPLICANT_EXTENSION_DS_KEY] << rb_mod unless datastore[REPLICANT_EXTENSION_DS_KEY].include? rb_mod
    end
  end

  #
  # Returns the unduplicated class associated with this module.
  #
  def orig_cls
    self.class.orig_cls
  end

  #
  # The path to the file in which the module can be loaded from.
  #
  def file_path
    self.class.file_path
  end

  #
  # Returns the current workspace
  #
  def workspace
    self.datastore['WORKSPACE'] ||
      (framework.db and framework.db.active and framework.db.workspace and framework.db.workspace.name)
  end

  #
  # Returns the username that instantiated this module, this tries a handful of methods
  # to determine what actual user ran this module.
  #
  def owner
    # Generic method to configure a module owner
    username = self.datastore['MODULE_OWNER'].to_s.strip

    # Specific method used by the commercial products
    if username.empty?
      username = self.datastore['PROUSER'].to_s.strip
    end

    # Fallback when neither prior method is available, common for msfconsole
    if username.empty?
      username = (ENV['LOGNAME'] || ENV['USERNAME'] || ENV['USER'] || "unknown").to_s.strip
    end

    username
  end

  #
  # Scans the parent module reference to populate additional information. This
  # is used to inherit common settings (owner, workspace, parent uuid, etc).
  #
  def register_parent(ref)
    self.datastore['WORKSPACE']    = (ref.datastore['WORKSPACE'] ? ref.datastore['WORKSPACE'].dup : nil)
    self.datastore['PROUSER']      = (ref.datastore['PROUSER']   ? ref.datastore['PROUSER'].dup   : nil)
    self.datastore['MODULE_OWNER'] = ref.owner.dup
    self.datastore['ParentUUID']   = ref.uuid.dup
  end

  #
  # Return a comma separated list of supported platforms, if any.
  #
  def platform_to_s
    platform.all? ? "All" : platform.names.join(", ")
  end

  #
  # Checks to see if this module is compatible with the supplied platform
  #
  def platform?(what)
    (platform & what).empty? == false
  end

  #
  # Returns true if this module is being debugged.
  #
  def debugging?
    datastore['DEBUG']
  end

  #
  # Raises a RuntimeError failure message. This is meant to be used for all non-exploits,
  # and allows specific classes to override.
  #
  # @param reason [String] A reason about the failure.
  # @param msg [String] (Optional) A message about the failure.
  # @raise [RuntimeError]
  # @return [void]
  # @note If you are writing an exploit, you don't use this API. Instead, please refer to the
  #       API documentation from lib/msf/core/exploit.rb.
  # @see Msf::Exploit#fail_with
  # @example
  #   fail_with('No Access', 'Unable to login')
  #
  def fail_with(reason, msg=nil)
    raise RuntimeError, "#{reason.to_s}: #{msg}"
  end


  ##
  #
  # Just some handy quick checks
  #
  ##

  #
  # Returns false since this is the real module
  #
  def self.cached?
    false
  end

  def required_cred_options
    @required_cred_options ||= lambda {
      self.options.select { |name, opt|
        (
          opt.type?('string') &&
          opt.required &&
          (opt.name.match(/user(name)*$/i) || name.match(/pass(word)*$/i))
        ) ||
        (
          opt.type?('bool') &&
          opt.required &&
          opt.name.match(/^allow_guest$/i)
        )
      }
    }.call
  end

  def black_listed_auth_filenames
    @black_listed_auth_filenames ||= lambda {
      [
        'fileformat',
        'browser'
      ]
    }.call
  end

  def post_auth?
    if self.kind_of?(Msf::Auxiliary::AuthBrute)
      return true
    else
      # Some modules will never be post auth, so let's not waste our time
      # determining it and create more potential false positives.
      # If these modules happen to be post auth for some reason, then we it
      # should manually override the post_auth? method as true.
      directory_name = self.fullname.split('/')[0..-2]
      black_listed_auth_filenames.each do |black_listed_name|
        return false if directory_name.include?(black_listed_name)
      end

      # Some modules create their own username and password datastore
      # options, not relying on the AuthBrute mixin. In that case we
      # just have to go through the options and try to identify them.
      !required_cred_options.empty?
    end
  end

  def default_cred?
    return false unless post_auth?

    cred_opts_with_default = required_cred_options.select { |name, opt|
      case opt.type
      when 'string'
        return true unless opt.default.blank?
      end
    }

    false
  end

  #
  # The array of zero or more platforms.
  #
  attr_reader   :platform

  #
  # The reference count for the module.
  #
  attr_reader   :references

  #
  # The license under which this module is provided.
  #
  attr_reader   :license

  #
  # The job identifier that this module is running as, if any.
  #
  attr_accessor :job_id

  #
  # The last exception to occur using this module
  #
  attr_accessor :error

  # An opaque bag of data to attach to a module. This is useful for attaching
  # some piece of identifying info on to a module before calling
  # {Msf::Simple::Exploit#exploit_simple} or
  # {Msf::Simple::Auxiliary#run_simple} for correlating where modules came
  # from.
  #
  attr_accessor :user_data

  protected

  #
  # Sets the modules unsupplied info fields to their default values.
  #
  def set_defaults
    self.module_info = {
      'Name'        => 'No module name',
      'Description' => 'No module description',
      'Version'     => '0',
      'Author'      => nil,
      'Arch'        => nil, # No architectures by default.
      'Platform'    => [],  # No platforms by default.
      'Ref'         => nil,
      'Privileged'  => false,
      'License'     => MSF_LICENSE,
      'Notes'       => {}
    }.update(self.module_info)
    self.module_store = {}
  end

  attr_writer   :platform, :references # :nodoc:
  attr_writer   :privileged # :nodoc:
  attr_writer   :license # :nodoc:

end
end
