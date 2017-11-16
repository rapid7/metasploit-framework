require 'msf/core/modules/metadata'

#
# Simple object for storing a modules metadata.
#
module Msf
module Modules
module Metadata

class Obj
  attr_reader :name
  attr_reader :full_name
  attr_reader :rank
  attr_reader :disclosure_date
  attr_reader :type
  attr_reader :author
  attr_reader :description
  attr_reader :references
  attr_reader :is_server
  attr_reader :is_client
  attr_reader :platform
  attr_reader :arch
  attr_reader :rport
  attr_reader :targets
  attr_reader :mod_time
  attr_reader :is_install_path
  attr_reader :ref_name

  def initialize(module_instance)
    @name = module_instance.name
    @full_name = module_instance.fullname
    @disclosure_date = module_instance.disclosure_date
    @rank = module_instance.rank.to_i
    @type = module_instance.type
    @description = module_instance.description.to_s.strip
    @author = module_instance.author.map{|x| x.to_s}
    @references = module_instance.references.map{|x| [x.ctx_id, x.ctx_val].join("-") }
    @is_server = (module_instance.respond_to?(:stance) and module_instance.stance == "aggressive")
    @is_client = (module_instance.respond_to?(:stance) and module_instance.stance == "passive")
    @platform = module_instance.platform_to_s
    @arch = module_instance.arch_to_s
    @rport = module_instance.datastore['RPORT'].to_s
    @path = module_instance.file_path
    @mod_time = ::File.mtime(@path) rescue Time.now
    @ref_name = module_instance.refname
    install_path = Msf::Config.install_root.to_s
    if (@path.to_s.include? (install_path))
      @path = @path.sub(install_path, '')
      @is_install_path = true
    end

    if module_instance.respond_to?(:targets) and module_instance.targets
      @targets = module_instance.targets.map{|x| x.name}
    end
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
end
end
end
end
