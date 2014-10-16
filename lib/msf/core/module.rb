# -*- coding: binary -*-
require 'msf/core'

module Msf

###
#
# The module base class is responsible for providing the common interface
# that is used to interact with modules at the most basic levels, such as
# by inspecting a given module's attributes (name, dsecription, version,
# authors, etc) and by managing the module's data store.
#
###
class Module
  autoload :Compatibility, 'msf/core/module/compatibility'
  autoload :DataStore, 'msf/core/module/data_store'
  autoload :ModuleInfo, 'msf/core/module/module_info'
  autoload :ModuleStore, 'msf/core/module/module_store'
  autoload :Options, 'msf/core/module/options'
  autoload :UI, 'msf/core/module/ui'

  include Msf::Module::Compatibility
  include Msf::Module::DataStore
  include Msf::Module::ModuleInfo
  include Msf::Module::ModuleStore
  include Msf::Module::Options
  include Msf::Module::UI

  # Make include public so we can runtime extend
  public_class_method :include

  class << self
    include Framework::Offspring

    #
    # Class method to figure out what type of module this is
    #
    def type
      raise NotImplementedError
    end

    def fullname
      type + '/' + refname
    end

    def shortname
      refname.split('/').last
    end

    #
    # Returns this module's ranking.
    #
    def rank
      (const_defined?('Rank')) ? const_get('Rank') : NormalRanking
    end

    #
    # Returns this module's ranking as a string representation.
    #
    def rank_to_s
      RankingName[rank]
    end

    #
    # Returns this module's ranking as a string for display.
    #
    def rank_to_h
      rank_to_s.gsub('Rank', '').downcase
    end
    #
    # The module's name that is assigned it it by the framework
    # or derived from the path that the module is loaded from.
    #
    attr_accessor :refname

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
  # This method allows modules to tell the framework if they are usable
  # on the system that they are being loaded on in a generic fashion.
  # By default, all modules are indicated as being usable.  An example of
  # where this is useful is if the module depends on something external to
  # ruby, such as a binary.
  #
  def self.is_usable
    true
  end

  require 'msf/core/module/author'
  require 'msf/core/module/platform_list'
  require 'msf/core/module/reference'
  require 'msf/core/module/target'
  require 'msf/core/module/auxiliary_action'
  require 'msf/core/module/has_actions'
  require 'msf/core/module/deprecated'

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
    self.author = Author.transform(module_info['Author'])
    self.arch = Rex::Transformer.transform(module_info['Arch'], Array, [ String ], 'Arch')
    self.platform = PlatformList.transform(module_info['Platform'])
    self.references = Rex::Transformer.transform(module_info['References'], Array, [ SiteReference, Reference ], 'Ref')

    # Create and initialize the option container for this module
    self.options = OptionContainer.new
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

    obj = self.class.new
    self.instance_variables.each { |k|
      v = instance_variable_get(k)
      v = v.dup rescue v
      obj.instance_variable_set(k, v)
    }

    obj.datastore    = self.datastore.copy
    obj.user_input   = self.user_input
    obj.user_output  = self.user_output
    obj.module_store = self.module_store.clone
    obj
  end

  #
  # Returns the module's framework full reference name.  This is the
  # short name that end-users work with (refname) plus the type
  # of module prepended.  Ex:
  #
  # payloads/windows/shell/reverse_tcp
  #
  def fullname
    self.class.fullname
  end

  #
  # Returns the module's framework reference name.  This is the
  # short name that end-users work with.  Ex:
  #
  # windows/shell/reverse_tcp
  #
  def refname
    self.class.refname
  end

  #
  # Returns the module's rank.
  #
  def rank
    self.class.rank
  end

  #
  # Returns the module's rank in string format.
  #
  def rank_to_s
    self.class.rank_to_s
  end

  #
  # Returns the module's rank in display format.
  #
  def rank_to_h
    self.class.rank_to_h
  end

  #
  # Returns the module's framework short name.  This is a
  # possibly conflicting name used for things like console
  # prompts.
  #
  # reverse_tcp
  #
  def shortname
    self.class.shortname
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
  # Checks to see if the target is vulnerable, returning unsupported if it's
  # not supported.
  #
  # This method is designed to be overriden by exploit modules.
  #
  def check
    Msf::Exploit::CheckCode::Unsupported
  end

  #
  # Returns the address of the last target host (rough estimate)
  #
  def target_host
    self.respond_to?('rhost') ? rhost : self.datastore['RHOST']
  end

  #
  # Returns the address of the last target port (rough estimate)
  #
  def target_port
    self.respond_to?('rport') ? rport : self.datastore['RPORT']
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
  # Return the module's abstract type.
  #
  def type
    raise NotImplementedError
  end

  #
  # Return a comma separated list of author for this module.
  #
  def author_to_s
    author.collect { |author| author.to_s }.join(", ")
  end

  #
  # Enumerate each author.
  #
  def each_author(&block)
    author.each(&block)
  end

  #
  # Return a comma separated list of supported architectures, if any.
  #
  def arch_to_s
    arch.join(", ")
  end

  #
  # Enumerate each architecture.
  #
  def each_arch(&block)
    arch.each(&block)
  end

  #
  # Return whether or not the module supports the supplied architecture.
  #
  def arch?(what)
    if (what == ARCH_ANY)
      true
    else
      arch.index(what) != nil
    end
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
  # Returns whether or not the module requires or grants high privileges.
  #
  def privileged?
    privileged == true
  end

  #
  # The default communication subsystem for this module.  We may need to move
  # this somewhere else.
  #
  def comm
    Rex::Socket::Comm::Local
  end

  #
  # Returns true if this module is being debugged.  The debug flag is set
  # by setting datastore['DEBUG'] to 1|true|yes
  #
  def debugging?
    (datastore['DEBUG'] || '') =~ /^(1|t|y)/i
  end

  #
  # Indicates whether the module supports IPv6. This is true by default,
  # but certain modules require additional work to be compatible or are
  # hardcoded in terms of application support and should be skipped.
  #
  def support_ipv6?
    true
  end

  #
  # This provides a standard set of search filters for every module.
  # The search terms are in the form of:
  #   {
  #     "text" => [  [ "include_term1", "include_term2", ...], [ "exclude_term1", "exclude_term2"], ... ],
  #     "cve" => [  [ "include_term1", "include_term2", ...], [ "exclude_term1", "exclude_term2"], ... ]
  #   }
  #
  # Returns true on no match, false on match
  #
  def search_filter(search_string)
    return false if not search_string

    search_string += " "

    # Split search terms by space, but allow quoted strings
    terms = search_string.split(/\"/).collect{|t| t.strip==t ? t : t.split(' ')}.flatten
    terms.delete('')

    # All terms are either included or excluded
    res = {}

    terms.each do |t|
      f,v = t.split(":", 2)
      if not v
        v = f
        f = 'text'
      end
      next if v.length == 0
      f.downcase!
      v.downcase!
      res[f] ||=[   [],    []   ]
      if v[0,1] == "-"
        next if v.length == 1
        res[f][1] << v[1,v.length-1]
      else
        res[f][0] << v
      end
    end

    k = res

    refs = self.references.map{|x| [x.ctx_id, x.ctx_val].join("-") }
    is_server    = (self.respond_to?(:stance) and self.stance == "aggressive")
    is_client    = (self.respond_to?(:stance) and self.stance == "passive")

    [0,1].each do |mode|
      match = false
      k.keys.each do |t|
        next if k[t][mode].length == 0

        k[t][mode].each do |w|
          # Reset the match flag for each keyword for inclusive search
          match = false if mode == 0

          # Convert into a case-insensitive regex
          r = Regexp.new(Regexp.escape(w), true)

          case t
            when 'text'
              terms = [self.name, self.fullname, self.description] + refs + self.author.map{|x| x.to_s}
              if self.respond_to?(:targets) and self.targets
                terms = terms + self.targets.map{|x| x.name}
              end
              match = [t,w] if terms.any? { |x| x =~ r }
            when 'name'
              match = [t,w] if self.name =~ r
            when 'path'
              match = [t,w] if self.fullname =~ r
            when 'author'
              match = [t,w] if self.author.map{|x| x.to_s}.any? { |a| a =~ r }
            when 'os', 'platform'
              match = [t,w] if self.platform_to_s =~ r or self.arch_to_s =~ r
              if not match and self.respond_to?(:targets) and self.targets
                match = [t,w] if self.targets.map{|x| x.name}.any? { |t| t =~ r }
              end
            when 'port'
              match = [t,w] if self.datastore['RPORT'].to_s =~ r
            when 'type'
              match = [t,w] if Msf::MODULE_TYPES.any? { |modt| w == modt and self.type == modt }
            when 'app'
              match = [t,w] if (w == "server" and is_server)
              match = [t,w] if (w == "client" and is_client)
            when 'cve'
              match = [t,w] if refs.any? { |ref| ref =~ /^cve\-/i and ref =~ r }
            when 'bid'
              match = [t,w] if refs.any? { |ref| ref =~ /^bid\-/i and ref =~ r }
            when 'osvdb'
              match = [t,w] if refs.any? { |ref| ref =~ /^osvdb\-/i and ref =~ r }
            when 'edb'
              match = [t,w] if refs.any? { |ref| ref =~ /^edb\-/i and ref =~ r }
          end
          break if match
        end
        # Filter this module if no matches for a given keyword type
        if mode == 0 and not match
          return true
        end
      end
      # Filter this module if we matched an exclusion keyword (-value)
      if mode == 1 and match
        return true
      end
    end

    false
  end

  #
  # Support fail_with for all module types, allow specific classes to override
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
  # Returns true if this module is an exploit module.
  #
  def exploit?
    (type == MODULE_EXPLOIT)
  end

  #
  # Returns true if this module is a payload module.
  #
  def payload?
    (type == MODULE_PAYLOAD)
  end

  #
  # Returns true if this module is an encoder module.
  #
  def encoder?
    (type == MODULE_ENCODER)
  end

  #
  # Returns true if this module is a nop module.
  #
  def nop?
    (type == MODULE_NOP)
  end

  #
  # Returns true if this module is an auxiliary module.
  #
  def auxiliary?
    (type == MODULE_AUX)
  end

  #
  # Returns true if this module is an post-exploitation module.
  #
  def post?
    (type == MODULE_POST)
  end

  #
  # Returns false since this is the real module
  #
  def self.cached?
    false
  end

  #
  # The array of zero or more authors.
  #
  attr_reader   :author
  #
  # The array of zero or more architectures.
  #
  attr_reader   :arch
  #
  # The array of zero or more platforms.
  #
  attr_reader   :platform
  #
  # The reference count for the module.
  #
  attr_reader   :references

  #
  # Whether or not this module requires privileged access.
  #
  attr_reader   :privileged
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

  #
  # A unique identifier for this module instance
  #
  attr_reader :uuid

protected
  attr_writer :uuid
  def generate_uuid
    self.uuid = Rex::Text.rand_text_alphanumeric(8).downcase
  end

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
    }.update(self.module_info)
    self.module_store = {}
  end

  #
  # Checks to see if a derived instance of a given module implements a method
  # beyond the one that is provided by a base class.  This is a pretty lame
  # way of doing it, but I couldn't find a better one, so meh.
  #
  def derived_implementor?(parent, method_name)
    (self.method(method_name).to_s.match(/#{parent}[^:]/)) ? false : true
  end

  attr_writer   :author, :arch, :platform, :references # :nodoc:
  attr_writer   :privileged # :nodoc:
  attr_writer   :license # :nodoc:

end

#
# Alias the data types so people can reference them just by Msf:: and not
# Msf::Module::
#
Author = Msf::Module::Author
Reference = Msf::Module::Reference
SiteReference = Msf::Module::SiteReference
Platform = Msf::Module::Platform
Target = Msf::Module::Target

end

