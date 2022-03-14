module Msf::Payload::Adapter
  # since an adapter wraps a single or stager payload, the cached size would be different for each, this means the cached
  # size can't be a single value and must be set to dynamic
  CachedSize = :dynamic

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

  # due to how payloads are made by combining all the modules, this is necessary to ensure that the adapted information
  # isn't placed into the final object
  def merge_info_adapted(key, info, opt)
    info[key] = [] unless info[key]
    info[key] << opt unless opt == info["Adapted#{key}"] || info[key].include?(opt)
  end
end
