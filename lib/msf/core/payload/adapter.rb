module Msf::Payload::Adapter
  # since an adapter wraps a single or stager payload, the cached size would be different for each, this means the cached
  # size can't be a single value and must be set to dynamic
  CachedSize = :dynamic

  def initialize(info={})
    super

    if self.is_a?(Msf::Payload::Stager)
      self.stage_arch = Rex::Transformer.transform(module_info['AdaptedArch'], Array, [ String ], 'AdaptedArch')
      self.stage_platform = Msf::Module::PlatformList.transform(module_info['AdaptedPlatform'])
    end
  end

  def compatible?(mod)
    if mod.type == Msf::MODULE_PAYLOAD
      return false if Set.new([module_info['AdaptedArch']]) != mod.arch.to_set

      return false if (Msf::Module::PlatformList.new(module_info['AdaptedPlatform']) & mod.platform).empty?
    end

    super
  end

  def payload_type
    return Msf::Payload::Type::Adapter
  end

  def merge_info_arch(info, opt)
    merge_info_adapted('Arch', info, opt)
  end

  def merge_info_platform(info, opt)
    merge_info_adapted('Platform', info, opt)
  end

  # Due to how payloads are made by combining all the modules, this is necessary to ensure that the adapted information
  # isn't placed into the final object. The current implementation requires that AdaptedArch/AdaptedPlatform are single
  # entries and not arrays of entries like the normal Arch/Platform info keys are.
  def merge_info_adapted(key, info, opt)
    if info[key] && !info[key].kind_of?(Array)
      info[key] = [ info[key] ]
    elsif !info[key]
      info[key] = []
    end

    if opt.kind_of?(Array)
      opt.each do |opt_val|
        next if info["Adapted#{key}"] == opt_val
        next if info[key].include?(opt_val)

        info[key] << opt_val
      end
    elsif opt != info["Adapted#{key}"] && !info[key].include?(opt)
      info[key] << opt
    end
  end
end
