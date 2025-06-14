require 'json'

#
# Simple object for storing a modules metadata.
#
module Msf
module Modules
module Metadata

class Obj
  # @return [Hash]
  attr_reader :actions
  # @return [String]
  attr_reader :name
  # @return [String]
  attr_reader :fullname
  # @return [Array<String>]
  attr_reader :aliases
  # @return [Integer]
  attr_reader :rank
  # @return [Date]
  attr_reader :disclosure_date
  # @return [String]
  attr_reader :type
  # @return [Array<String>]
  attr_reader :author
  # @return [String]
  attr_reader :description
  # @return [Array<String>]
  attr_reader :references
  # @return [String]
  attr_reader :platform
  # @return [Msf::Module::PlatformList]
  attr_reader :platform_list
  # @return [String]
  attr_reader :arch
  # @return [Integer]
  attr_reader :rport
  # @return [Array<Integer>]
  attr_reader :autofilter_ports
  # @return [Array<String>]
  attr_reader :autofilter_services
  # @return [Array<String>, nil]
  attr_reader :targets
  # @return [Time]
  attr_reader :mod_time
  # @return [Boolean]
  attr_reader :is_install_path
  # @return [String]
  attr_reader :ref_name
  # @return [Boolean]
  attr_reader :check
  # @return [Boolean]
  attr_reader :post_auth
  alias :post_auth? :post_auth # Mirror the Module class
  # @return [Boolean]
  attr_reader :default_credential
  alias :default_cred? :default_credential # Mirror the Module class
  # @return [Hash]
  attr_reader :notes
  # @return [Array<String>]
  attr_reader :session_types
  # @return [Integer] The type of payload, e.g. Single, Stager, Adapter
  attr_reader :payload_type
  # @return [String, nil] Name of the adapter if applicable
  attr_reader :adapter_refname
  # @return [String, nil] Name of the adapted payload if applicable
  attr_reader :adapted_refname
  # @return [Boolean] Whether or not the payload is staged
  attr_reader :staged
  # @return [String, nil] Name of the stage if applicable
  attr_reader :stage_refname
  # @return [String, nil] Name of the stager if applicable
  attr_reader :stager_refname

  def initialize(module_instance, obj_hash = nil)
    unless obj_hash.nil?
      init_from_hash(obj_hash)
      return
    end

    @name               = module_instance.name
    @fullname           = module_instance.realname
    @aliases            = module_instance.aliases
    @disclosure_date    = module_instance.disclosure_date
    @rank               = module_instance.rank.to_i
    @type               = module_instance.type
    @description        = module_instance.description.to_s.strip
    @author             = module_instance.author.map{|x| x.to_s}
    @references         = module_instance.references.map{|x| [x.ctx_id, x.ctx_val].join("-") }
    @post_auth          = module_instance.post_auth?
    @default_credential = module_instance.default_cred?

    @platform           = module_instance.platform_to_s
    @platform_list      = module_instance.platform
    # Done to ensure that differences do not show up for the same array grouping
    sort_platform_string

    @arch               = module_instance.arch_to_s
    @rport              = module_instance.datastore['RPORT']
    @path               = module_instance.file_path
    @mod_time           = ::File.mtime(@path) rescue Time.now
    @ref_name           = module_instance.class.refname
    @needs_cleanup      = module_instance.respond_to?(:needs_cleanup) && module_instance.needs_cleanup

    if module_instance.respond_to?(:actions)
      @actions = module_instance.actions.sort_by(&:name).map do |action|
        {
          'name' => action.name,
          'description' => action.description
        }
      end
    end

    if module_instance.respond_to?(:autofilter_ports)
      @autofilter_ports = module_instance.autofilter_ports
    end
    if module_instance.respond_to?(:autofilter_services)
      @autofilter_services = module_instance.autofilter_services
    end

    install_path = Msf::Config.install_root.to_s
    if (@path.to_s.include? (install_path))
      @path = @path.sub(install_path, '')
      @is_install_path = true
    end

    if module_instance.respond_to?(:targets) and module_instance.targets
      @targets = module_instance.targets.map{|x| x.name}
    end

    # Store whether a module has a check method
    @check = module_instance.has_check?

    @notes = module_instance.notes

    @session_types = module_instance.respond_to?(:session_types) && module_instance.session_types

    if module_instance.respond_to?(:payload_type)
      @payload_type = module_instance.payload_type
      @staged = module_instance.staged?
    end
    if @staged
      @stage_refname = module_instance.stage_refname
      @stager_refname = module_instance.stager_refname
    end
    if @payload_type == Payload::Type::Adapter
      @adapter_refname = module_instance.adapter_refname
      @adapted_refname = module_instance.adapted_refname
    end

    # Due to potentially non-standard ASCII we force UTF-8 to ensure no problem with JSON serialization
    force_encoding(::Encoding::UTF_8)
  end

  #
  # Returns the JSON representation of the module metadata
  #
  def to_json(*args)
    data = {
      'name'               => @name,
      'fullname'           => @fullname,
      'aliases'            => @aliases,
      'rank'               => @rank,
      'disclosure_date'    => @disclosure_date.nil? ? nil : @disclosure_date.to_s,
      'type'               => @type,
      'author'             => @author,
      'description'        => @description,
      'references'         => @references,
      'platform'           => @platform,
      'arch'               => @arch,
      'rport'              => @rport,
      'autofilter_ports'   => @autofilter_ports,
      'autofilter_services'=> @autofilter_services,
      'targets'            => @targets,
      'mod_time'           => @mod_time.to_s,
      'path'               => @path,
      'is_install_path'    => @is_install_path,
      'ref_name'           => @ref_name,
      'check'              => @check,
      'post_auth'          => @post_auth,
      'default_credential' => @default_credential,
      'notes'              => @notes,
      'session_types'      => @session_types,
      'needs_cleanup'      => @needs_cleanup,
    }

    data['actions'] = @actions if @actions

    if @payload_type
      payload_data = {
        'payload_type'       => @payload_type,
        'adapter_refname'    => @adapter_refname,
        'adapted_refname'    => @adapted_refname,
        'adapted'            => @adapted,
        'staged'             => @staged,
        'stage_refname'      => @stage_refname,
        'stager_refname'     => @stager_refname,
      }.compact
      data.merge!(payload_data)
    end

    data.to_json(*args)
  end

  #
  # Initialize this object from a hash
  #
  def self.from_hash(obj_hash)
    return Obj.new(nil, obj_hash)
  end

  def update_mod_time(mod_time)
    @mod_time = mod_time
  end

  def path
    if @is_install_path
      return ::File.join(Msf::Config.install_root, @path)
    end

    @path
  end

  #######
  private
  #######

  def init_from_hash(obj_hash)
    @actions             = obj_hash['actions']
    @name                = obj_hash['name']
    @fullname            = obj_hash['fullname']
    @aliases             = obj_hash['aliases'] || []
    @disclosure_date     = obj_hash['disclosure_date'].nil? ? nil : Time.parse(obj_hash['disclosure_date'])
    @rank                = obj_hash['rank']
    @type                = obj_hash['type']
    @description         = obj_hash['description']
    @author              = obj_hash['author'].nil? ? [] : obj_hash['author']
    @references          = obj_hash['references']
    @platform            = obj_hash['platform']
    @platform_list       = parse_platform_list(@platform)
    @arch                = obj_hash['arch']
    @rport               = obj_hash['rport']
    @mod_time            = Time.parse(obj_hash['mod_time'])
    @ref_name            = obj_hash['ref_name']
    @path                = obj_hash['path']
    @is_install_path     = obj_hash['is_install_path']
    @targets             = obj_hash['targets']
    @check               = obj_hash['check'] ? true : false
    @post_auth           = obj_hash['post_auth']
    @default_credential  = obj_hash['default_credential']
    @notes               = obj_hash['notes'].nil? ? {} : obj_hash['notes']
    @needs_cleanup       = obj_hash['needs_cleanup']
    @session_types       = obj_hash['session_types']
    @autofilter_ports    = obj_hash['autofilter_ports']
    @autofilter_services = obj_hash['autofilter_services']
    @payload_type        = obj_hash['payload_type']
    @adapter_refname     = obj_hash['adapter_refname']
    @adapted_refname     = obj_hash['adapted_refname']
    @staged              = obj_hash['staged']
    @stage_refname       = obj_hash['stage_refname']
    @stager_refname      = obj_hash['stager_refname']
  end

  def sort_platform_string
    arr = @platform.split(',')
    unless arr.empty?
      arr.each {|value| value.strip!}
      if arr.length > 1
        @platform = arr.sort.join(',')
      else
        @platform = arr[0]
      end
    end
  end

  def force_encoding(encoding)
    if @actions
      # Encode the actions hashes, assumes that there are no nested hashes
      @actions = @actions.map do |action|
        action.map do |k, v|
          new_key = k.dup.force_encoding(encoding)
          new_value = v.is_a?(String) ? v.dup.force_encoding(encoding) : v
          [new_key, new_value]
        end.to_h
      end
    end
    @name = @name.dup.force_encoding(encoding)
    @fullname = @fullname.dup.force_encoding(encoding)
    @description = @description.dup.force_encoding(encoding)
    @author = @author.map {|a| a.dup.force_encoding(encoding)}
    @references = @references.map {|r| r.dup.force_encoding(encoding)}
  end

  def parse_platform_list(platform_string)
    return nil if platform_string.nil?

    if platform_string.casecmp?('All')
      # empty string represents all platforms in Msf::Module::PlatformList
      platforms = ['']
    else
      platforms = platform_string.split(',')
    end
    Msf::Module::PlatformList.transform(platforms)
  end

end
end
end
end
