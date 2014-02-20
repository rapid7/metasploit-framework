# -*- coding: binary -*-

module Msf
module RPC
class RPC_Module < RPC_Base

  def rpc_exploits
    { "modules" => self.framework.exploits.keys }
  end

  def rpc_auxiliary
    { "modules" => self.framework.auxiliary.keys }
  end

  def rpc_payloads
    { "modules" => self.framework.payloads.keys }
  end

  def rpc_encoders
    { "modules" => self.framework.encoders.keys }
  end

  def rpc_nops
    { "modules" => self.framework.nops.keys }
  end

  def rpc_post
    { "modules" => self.framework.post.keys }
  end

  def rpc_info(mtype, mname)
    m = _find_module(mtype,mname)
    res = {}

    res['name'] = m.name
    res['description'] = m.description
    res['license'] = m.license
    res['filepath'] = m.file_path
    res['rank'] = m.rank.to_i

    res['references'] = []
    m.references.each do |r|
      res['references'] << [r.ctx_id, r.ctx_val]
    end

    res['authors'] = []
    m.each_author do |a|
      res['authors'] << a.to_s
    end

    if(m.type == "exploit")
      res['targets'] = {}
      m.targets.each_index do |i|
        res['targets'][i] = m.targets[i].name
      end

      if (m.default_target)
        res['default_target'] = m.default_target
      end
    end

    if(m.type == "auxiliary")
      res['actions'] = {}
      m.actions.each_index do |i|
        res['actions'][i] = m.actions[i].name
      end

      if (m.default_action)
        res['default_action'] = m.default_action
      end
    end

    res
  end


  def rpc_compatible_payloads(mname)
    m   = _find_module('exploit',mname)
    res = {}
    res['payloads'] = []
    m.compatible_payloads.each do |k|
      res['payloads'] << k[0]
    end

    res
  end

  def rpc_compatible_sessions(mname)
    m   = _find_module('post',mname)
    res = {}
    res['sessions'] = m.compatible_sessions

    res
  end

  def rpc_target_compatible_payloads(mname, target)
    m   = _find_module('exploit',mname)
    res = {}
    res['payloads'] = []
    m.datastore['TARGET'] = target.to_i
    m.compatible_payloads.each do |k|
      res['payloads'] << k[0]
    end

    res
  end

  def rpc_options(mtype, mname)
    m = _find_module(mtype,mname)
    res = {}

    m.options.each_key do |k|
      o = m.options[k]
      res[k] = {
        'type'     => o.type,
        'required' => o.required,
        'advanced' => o.advanced,
        'evasion'  => o.evasion,
        'desc'     => o.desc
      }

      if(not o.default.nil?)
        res[k]['default'] = o.default
      end

      if(o.enums.length > 1)
        res[k]['enums'] = o.enums
      end
    end

    res
  end

  def rpc_execute(mtype, mname, opts)
    mod = _find_module(mtype,mname)
    case mtype
      when 'exploit'
        _run_exploit(mod, opts)
      when 'auxiliary'
        _run_auxiliary(mod, opts)
      when 'payload'
        _run_payload(mod, opts)
      when 'post'
        _run_post(mod, opts)
    end

  end

  def rpc_encode_formats
    # Supported formats
    Msf::Simple::Buffer.transform_formats + Msf::Util::EXE.to_executable_fmt_formats
  end

  def rpc_encode(data, encoder, options)
    # Load supported formats
    supported_formats = Msf::Simple::Buffer.transform_formats + Msf::Util::EXE.to_executable_fmt_formats

    if (fmt = options['format'])
      if not supported_formats.include?(fmt)
        error(500, "Invalid Format: #{fmt}")
      end
    end

    badchars = ''
    if options['badchars']
      badchars = options['badchars']
    end

    platform = nil
    if options['platform']
      platform = Msf::Module::PlatformList.transform(options['platform'])
    end

    arch = nil
    if options['arch']
      arch = options['arch']
    end

    ecount = 1
    if options['ecount']
      ecount = options['ecount'].to_i
    end

    exeopts = {
      :inject => options['inject'],
      :template => options['altexe'],
      :template_path => options['exedir']
    }

    # If we were given addshellcode for a win32 payload,
    # create a double-payload; one running in one thread, one running in the other
    if options['addshellcode']
      buf = Msf::Util::EXE.win32_rwx_exec_thread(buf,0,'end')
      file = ::File.new(options['addshellcode'])
      file.binmode
      buf << file.read
      file.close
    end

    enc = self.framework.encoders.create(encoder)

    begin
      # Imports options
      enc.datastore.update(options)

      raw  = data.unpack("C*").pack("C*")

      1.upto(ecount) do |iteration|
        # Encode it up
        raw = enc.encode(raw, badchars, nil, platform)
      end

      output = Msf::Util::EXE.to_executable_fmt(self.framework, arch, platform, raw, fmt, exeopts)

      if not output
        fmt ||= "ruby"
        output = Msf::Simple::Buffer.transform(raw, fmt)
      end

      # How to warn?
      #if exeopts[:fellback]
      #	$stderr.puts(OutError + "Warning: Falling back to default template: #{exeopts[:fellback]}")
      #end

      { "encoded" => output.to_s }
    rescue => e
      error(500, "#{enc.refname} failed: #{e} #{e.backtrace}")
    end
  end

private

  def _find_module(mtype,mname)

    if mname !~ /^(exploit|payload|nop|encoder|auxiliary|post)\//
      mname = mtype + "/" + mname
    end

    mod = self.framework.modules.create(mname)

    error(500, "Invalid Module") if not mod
    mod
  end

  def _run_exploit(mod, opts)
    s = Msf::Simple::Exploit.exploit_simple(mod, {
      'Payload'  => opts['PAYLOAD'],
      'Target'   => opts['TARGET'],
      'RunAsJob' => true,
      'Options'  => opts
    })
    {
      "job_id" => mod.job_id,
      "uuid" => mod.uuid
    }
  end

  def _run_auxiliary(mod, opts)
    Msf::Simple::Auxiliary.run_simple(mod, {
      'Action'   => opts['ACTION'],
      'RunAsJob' => true,
      'Options'  => opts
    })
    {
      "job_id" => mod.job_id,
      "uuid" => mod.uuid
    }
  end

  def _run_post(mod, opts)
    Msf::Simple::Post.run_simple(mod, {
      'RunAsJob' => true,
      'Options'  => opts
    })
    {
      "job_id" => mod.job_id,
      "uuid" => mod.uuid
    }
  end

  def _run_payload(mod, opts)
    badchars = opts['BadChars'] || ''
    fmt = opts['Format'] || 'raw'
    force = opts['ForceEncode'] || false
    template = opts['Template'] || nil
    plat = opts['Platform'] || nil
    keep = opts['KeepTemplateWorking'] || false
    force = opts['ForceEncode'] || false
    sled_size = opts['NopSledSize'].to_i || 0
    iter = opts['Iterations'].to_i || 0

    begin
      res = Msf::Simple::Payload.generate_simple(mod, {
        'BadChars'    => badchars,
        'Encoder'     => opts['Encoder'],
        'Format'      => fmt,
        'NoComment'   => true,
        'NopSledSize' => sled_size,
        'Options'     => opts,
        'ForceEncode' => force,
        'Template'    => template,
        'Platform'    => plat,
        'KeepTemplateWorking' => keep,
        'Iterations'  => iter
      })

      { "payload" => res }
    rescue ::Exception => e
      error(500, "failed to generate: #{e.message}")
    end
  end


end
end
end

