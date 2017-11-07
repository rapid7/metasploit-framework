#
# Simple accessor object for storing module metadata.
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

  def initialize(module_instance)
    @name = module_instance.name
    @full_name = module_instance.fullname
    @disclosure_date = module_instance.disclosure_date
    @rank = module_instance.rank
    @type = module_instance.type
    @description = module_instance.description
    @author = module_instance.author.map{|x| x.to_s}
    @references = module_instance.references.map{|x| [x.ctx_id, x.ctx_val].join("-") }
    @is_server = (module_instance.respond_to?(:stance) and module_instance.stance == "aggressive")
    @is_client = (module_instance.respond_to?(:stance) and module_instance.stance == "passive")
    @platform = module_instance.platform_to_s
    @arch = module_instance.arch_to_s
    @rport = module_instance.datastore['RPORT'].to_s

    if module_instance.respond_to?(:targets) and module_instance.targets
      @targets = module_instance.targets.map{|x| x.name}
    end
  end
end
end
end
end
