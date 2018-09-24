# -*- coding: binary -*-
require 'msf/core/modules/external'

class Msf::Modules::External::Shim
  def self.generate(module_path, framework)
    mod = Msf::Modules::External.new(module_path, framework: framework)
    return '' unless mod.meta
    case mod.meta['type']
    when 'remote_exploit'
      remote_exploit(mod)
    when 'remote_exploit_cmd_stager'
      remote_exploit_cmd_stager(mod)
    when 'capture_server'
      capture_server(mod)
    when 'dos'
      dos(mod)
    when 'single_scanner'
      single_scanner(mod)
    when 'single_host_login_scanner'
      single_host_login_scanner(mod)
    when 'multi_scanner'
      multi_scanner(mod)
    else
      nil
    end
  end

  def self.render_template(name, meta = {})
    template = File.join(File.dirname(__FILE__), 'templates', name)
    ERB.new(File.read(template)).result(binding)
  end

  def self.common_metadata(meta = {})
    render_template('common_metadata.erb', meta)
  end

  def self.common_check(meta = {})
    render_template('common_check.erb', meta)
  end

  def self.mod_meta_common(mod, meta = {}, ignore_options: [])
    meta[:path]        = mod.path.dump
    meta[:name]        = mod.meta['name'].dump
    meta[:description] = mod.meta['description'].dump
    meta[:authors]     = mod.meta['authors'].map(&:dump).join(",\n          ")
    meta[:license]     = mod.meta['license'].nil? ? 'MSF_LICENSE' : mod.meta['license']

    options = mod.meta['options'].reject {|n, _| ignore_options.include? n}

    meta[:options]     = options.map do |n, o|
      if o['values']
        "Opt#{o['type'].camelize}.new(#{n.dump},
          [#{o['required']}, #{o['description'].dump}, #{o['default'].inspect}, #{o['values'].inspect}])"
      else
        "Opt#{o['type'].camelize}.new(#{n.dump},
          [#{o['required']}, #{o['description'].dump}, #{o['default'].inspect}])"
      end
    end.join(",\n          ")

    meta[:capabilities] = mod.meta['capabilities']
    meta[:notes] = transform_notes(mod.meta['notes'])
    meta
  end

  def self.mod_meta_exploit(mod, meta = {})
    meta[:rank]        = mod.meta['rank'].nil? ? 'NormalRanking' : "#{mod.meta['rank'].capitalize}Ranking"
    meta[:date]        = mod.meta['date'].dump
    meta[:wfsdelay]    = mod.meta['wfsdelay'] || 5
    meta[:privileged]  = mod.meta['privileged'].inspect
    meta[:platform]    = mod.meta['targets'].map do |t|
      t['platform'].dump
    end.uniq.join(",\n          ")
    meta[:arch]        = mod.meta['targets'].map do |t|
      t['arch'].dump
    end.uniq.join(",\n          ")
    meta[:references]  = mod.meta['references'].map do |r|
      "[#{r['type'].upcase.dump}, #{r['ref'].dump}]"
    end.join(",\n          ")
    meta[:targets]     = mod.meta['targets'].map do |t|
      "[#{t['platform'].dump} + ' ' + #{t['arch'].dump}, {'Arch' => ARCH_#{t['arch'].upcase}, 'Platform' => #{t['platform'].dump} }]"
    end.join(",\n          ")
    meta
  end

  def self.remote_exploit(mod)
    meta = mod_meta_common(mod)
    meta = mod_meta_exploit(mod, meta)
    render_template('remote_exploit.erb', meta)
  end

  def self.remote_exploit_cmd_stager(mod)
    meta = mod_meta_common(mod, ignore_options: ['command'])
    meta = mod_meta_exploit(mod, meta)
    meta[:command_stager_flavor] = mod.meta['payload']['command_stager_flavor'].dump
    render_template('remote_exploit_cmd_stager.erb', meta)
  end

  def self.capture_server(mod)
    meta = mod_meta_common(mod)
    render_template('capture_server.erb', meta)
  end

  def self.single_scanner(mod)
    meta = mod_meta_common(mod, ignore_options: ['rhost'])
    meta[:date] = mod.meta['date'].dump
    meta[:references] = mod.meta['references'].map do |r|
      "[#{r['type'].upcase.dump}, #{r['ref'].dump}]"
    end.join(",\n          ")
    render_template('single_scanner.erb', meta)
  end

  def self.single_host_login_scanner(mod)
    meta = mod_meta_common(mod, ignore_options: ['rhost'])
    meta[:date] = mod.meta['date'].dump
    meta[:references] = mod.meta['references'].map do |r|
      "[#{r['type'].upcase.dump}, #{r['ref'].dump}]"
    end.join(",\n          ")

    render_template('single_host_login_scanner.erb', meta)
  end

  def self.multi_scanner(mod)
    meta = mod_meta_common(mod)
    meta[:date] = mod.meta['date'].dump
    meta[:references] = mod.meta['references'].map do |r|
      "[#{r['type'].upcase.dump}, #{r['ref'].dump}]"
    end.join(",\n          ")

    render_template('multi_scanner.erb', meta)
  end

  def self.dos(mod)
    meta = mod_meta_common(mod)
    meta[:date] = mod.meta['date'].dump
    meta[:references] = mod.meta['references'].map do |r|
      "[#{r['type'].upcase.dump}, #{r['ref'].dump}]"
    end.join(",\n          ")

    render_template('dos.erb', meta)
  end

  #
  # In case certain notes are not properly capitalized in the external module definition,
  # ensure that they are properly capitalized before rendering.
  #
  def self.transform_notes(notes)
    notes.reduce({}) do |acc, (key, val)|
      acc[key.upcase] = val
      acc
    end
  end

end
