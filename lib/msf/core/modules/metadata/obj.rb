require 'msf/core/modules/metadata'
require 'json'

#
# Simple object for storing a modules metadata.
#
module Msf
module Modules
module Metadata

class Obj
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
  # @return [Boolean]
  attr_reader :platform
  # @return [String]
  attr_reader :arch
  # @return [Integer]
  attr_reader :rport
  # @return [Array<Integer>]
  attr_reader :autofilter_ports
  # @return [Array<String>]
  attr_reader :autofilter_services
  # @return [Array<String>]
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
  # @return [Boolean]
  attr_reader :default_credential
  # @return [Hash]
  attr_reader :notes

  def initialize(module_instance, obj_hash = nil)
    unless obj_hash.nil?
      init_from_hash(obj_hash)
      return
    end

    @name               = module_instance.name
    @fullname           = module_instance.fullname
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
    # Done to ensure that differences do not show up for the same array grouping
    sort_platform_string

    @arch               = module_instance.arch_to_s
    @rport              = module_instance.datastore['RPORT']
    @path               = module_instance.file_path
    @mod_time           = ::File.mtime(@path) rescue Time.now
    @ref_name           = module_instance.refname
    @needs_cleanup      = module_instance.respond_to?(:needs_cleanup) && module_instance.needs_cleanup

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
    @check = module_instance.respond_to?(:check) ? true : false

    @notes = module_instance.notes

    # Due to potentially non-standard ASCII we force UTF-8 to ensure no problem with JSON serialization
    force_encoding(Encoding::UTF_8)
  end

  #
  # Returns the JSON representation of the module metadata
  #
  def to_json(*args)
    {
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
      'needs_cleanup'      => @needs_cleanup
    }.to_json(*args)
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
    @name               = obj_hash['name']
    @fullname           = obj_hash['fullname']
    @aliases            = obj_hash['aliases'] || []
    @disclosure_date    = obj_hash['disclosure_date'].nil? ? nil : Time.parse(obj_hash['disclosure_date'])
    @rank               = obj_hash['rank']
    @type               = obj_hash['type']
    @description        = obj_hash['description']
    @author             = obj_hash['author'].nil? ? [] : obj_hash['author']
    @references         = obj_hash['references']
    @platform           = obj_hash['platform']
    @arch               = obj_hash['arch']
    @rport              = obj_hash['rport']
    @mod_time           = Time.parse(obj_hash['mod_time'])
    @ref_name           = obj_hash['ref_name']
    @path               = obj_hash['path']
    @is_install_path    = obj_hash['is_install_path']
    @targets            = obj_hash['targets'].nil? ? [] : obj_hash['targets']
    @check              = obj_hash['check'] ? true : false
    @post_auth          = obj_hash['post_auth']
    @default_credential = obj_hash['default_credential']
    @notes              = obj_hash['notes'].nil? ? {} : obj_hash['notes']
    @needs_cleanup      = obj_hash['needs_cleanup']

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
    @name.force_encoding(encoding)
    @fullname.force_encoding(encoding)
    @description.force_encoding(encoding)
    @author.each {|a| a.force_encoding(encoding)}
    @references.each {|r| r.force_encoding(encoding)}
  end

end
end
end
end
