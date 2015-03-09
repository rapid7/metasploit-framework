# -*- coding: binary -*-
###
#
#
###

module Msf
module Util

#
# The class provides helper methods for verifying and updating the embedded CachedSize
# constant within payload modules.
#

class PayloadCachedSize

  def self.update_cache_constant(data, cached_size)
    data.
      gsub(/^\s*CachedSize\s*=\s*(\d+|:dynamic).*/, '').
      gsub(/^(module Metasploit\d+)\s*\n/) do |m|
        "#{m.strip}\n\n  CachedSize = #{cached_size}\n\n"
      end
  end

  def self.update_cached_size(mod, cached_size)
    mod_data = ""

    ::File.open(mod.file_path, 'rb') do |fd|
      mod_data = fd.read(fd.stat.size)
    end

    ::File.open(mod.file_path, 'wb') do |fd|
      fd.write update_cache_constant(mod_data, cached_size)
    end
  end

  def self.update_module_cached_size(mod)
    update_cached_size(mod, compute_cached_size(mod))
  end

  def self.compute_cached_size(mod)
    return :dynamic if is_dynamic?(mod)
    return mod.new.size
  end

  def self.is_dynamic?(mod,generation_count=5)
    [*(1..generation_count)].map{|x| mod.new.size}.uniq.length != 1
  end

  def self.is_cached_size_accurate?(mod)
    return true if mod.dynamic_size?
    return false if mod.cached_size.nil?
    mod.cached_size == mod.new.size
  end

end

end
end
