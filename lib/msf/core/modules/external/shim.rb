# -*- coding: binary -*-
require 'msf/core/modules/external'
require 'msf/core/modules/external/bridge'

class Msf::Modules::External::Shim
  def self.generate(module_path)
    mod = Msf::Modules::External::Bridge.open(module_path)
    return '' unless mod.meta
    case mod.meta['type']
    when 'remote_exploit_cmd_stager'
      remote_exploit_cmd_stager(mod)
    end
  end

  def self.render_template(name, meta = {})
    template = File.join(File.dirname(__FILE__), 'templates', name)
    ERB.new(File.read(template)).result(binding)
  end

  def self.common_metadata(meta = {})
    render_template('common_metadata.erb', meta)
  end

  def self.mod_meta_common(mod, meta = {})
    meta[:path]        = mod.path.dump
    meta[:name]        = mod.meta['name'].dump
    meta[:description] = mod.meta['description'].dump
    meta[:authors]     = mod.meta['authors'].map(&:dump).join(",\n          ")
    meta[:date]        = mod.meta['date'].dump
    meta[:references]  = mod.meta['references'].map do |r|
      "[#{r['type'].upcase.dump}, #{r['ref'].dump}]"
    end.join(",\n          ")

    meta[:options]     = mod.meta['options'].map do |n, o|
      "Opt#{o['type'].capitalize}.new(#{n.dump},
        [#{o['required']}, #{o['description'].dump}, #{o['default'].inspect}])"
    end.join(",\n          ")
    meta
  end

  def self.mod_meta_exploit(mod, meta = {})
    meta[:wfsdelay]    = mod.meta['wfsdelay'] || 5
    meta[:privileged]  = mod.meta['privileged'].inspect
    meta[:platform]    = mod.meta['targets'].map do |t|
      t['platform'].dump
    end.uniq.join(",\n          ")
    meta[:targets]     = mod.meta['targets'].map do |t|
      "[#{t['platform'].dump} + ' ' + #{t['arch'].dump}, {'Arch' => ARCH_#{t['arch'].upcase}, 'Platform' => #{t['platform'].dump} }]"
    end.join(",\n          ")
    meta
  end

  def self.remote_exploit_cmd_stager(mod)
    meta = mod_meta_common(mod)
    meta = mod_meta_exploit(mod, meta)
    meta[:command_stager_flavor] = mod.meta['payload']['command_stager_flavor'].dump
    render_template('remote_exploit_cmd_stager.erb', meta)
  end
end
