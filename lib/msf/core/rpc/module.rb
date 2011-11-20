##
# $Id$
##

module Msf
module RPC
class Module < Base

	def exploits(token)
		authenticate(token)
		{ "modules" => @framework.exploits.keys }
	end

	def auxiliary(token)
		authenticate(token)
		{ "modules" => @framework.auxiliary.keys }
	end

	def payloads(token)
		authenticate(token)
		{ "modules" => @framework.payloads.keys }
	end

	def encoders(token)
		authenticate(token)
		{ "modules" => @framework.encoders.keys }
	end

	def nops(token)
		authenticate(token)
		{ "modules" => @framework.nops.keys }
	end

	def post(token)
		authenticate(token)
		{ "modules" => @framework.post.keys }
	end


	def info(token, mtype, mname)
		authenticate(token)

		m = _find_module(mtype,mname)
		res = {}

		res['name'] = m.name
		res['description'] = m.description
		res['license'] = m.license
		res['filepath'] = m.file_path
		res['version'] = m.version
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


	def compatible_payloads(token, mname)
		authenticate(token)
		m = _find_module('exploit',mname)
		if(not m)
			raise ::XMLRPC::FaultException.new(404, "unknown module")
		end

		res = {}
		res['payloads'] = []
		m.compatible_payloads.each do |k|
			res['payloads'] << k[0]
		end

		res
	end

	def compatible_sessions(token, mname)
		authenticate(token)
		m = _find_module('post',mname)
		if(not m)
			raise ::XMLRPC::FaultException.new(404, "unknown module")
		end

		res = {}
		res['sessions'] = m.compatible_sessions

		res
	end

	def target_compatible_payloads(token, mname, target)
		authenticate(token)
		m = _find_module('exploit',mname)
		if(not m)
			raise ::XMLRPC::FaultException.new(404, "unknown module")
		end

		res = {}
		res['payloads'] = []
		m.datastore['TARGET'] = target.to_i
		m.compatible_payloads.each do |k|
			res['payloads'] << k[0]
		end

		res
	end

	def options(token, mtype, mname)
		authenticate(token)

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

	def execute(token, mtype, mname, opts)
		authenticate(token)

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

	def encode(token, data, encoder, options)
		authenticate(token)
		buf = Rex::Text.decode_base64(data)

		# Load supported formats
		supported_formats = Msf::Simple::Buffer.transform_formats + Msf::Util::EXE.to_executable_fmt_formats

		if (fmt = options['format'])
			if not supported_formats.include?(fmt)
				raise ::XMLRPC::FaultException.new(500, "failed to generate: invalid format: #{fmt}")
			end
		end

		badchars = ''
		if options['badchars']
			badchars = Rex::Text.hex_to_raw(options['badchars'])
		end

		plat = nil
		if options['plat']
			plat = Msf::Module::PlatformList.transform(val)
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

		enc = @framework.encoders.create(encoder)

		begin
			# Imports options
			enc.datastore.update(options)

			raw  = buf.dup

			1.upto(ecount) do |iteration|
				# Encode it up
				raw = enc.encode(raw, badchars, nil, plat)
			end

			output = Msf::Util::EXE.to_executable_fmt(@framework, arch, plat, raw, fmt, exeopts)

			if not output
				fmt ||= "ruby"
				output = Msf::Simple::Buffer.transform(raw, fmt)
			end

			# How to warn?
			#if exeopts[:fellback]
			#	$stderr.puts(OutError + "Warning: Falling back to default template: #{exeopts[:fellback]}")
			#end

			{"encoded" => Rex::Text.encode_base64(output.to_s)}
		rescue => e
			raise ::XMLRPC::FaultException.new(500, "#{enc.refname} failed: #{e} #{e.backtrace}")
		end
	end

private

	def _find_module(mtype,mname)
		mod = @framework.modules.create(mname)

		if(not mod)
			raise ::XMLRPC::FaultException.new(404, "unknown module")
		end

		mod
	end

	def _run_exploit(mod, opts)
		s = Msf::Simple::Exploit.exploit_simple(mod, {
			'Payload'  => opts['PAYLOAD'],
			'Target'   => opts['TARGET'],
			'RunAsJob' => true,
			'Options'  => opts
		})
		{"result" => "success"}
	end

	def _run_auxiliary(mod, opts)
		Msf::Simple::Auxiliary.run_simple(mod, {
			'Action'   => opts['ACTION'],
			'RunAsJob' => true,
			'Options'  => opts
		})
		{"result" => "success"}
	end

	def _run_payload(mod, opts)
		badchars = [opts['BadChars'] || ''].pack("H*")
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

			{"result" => "success", "payload" => res.unpack("H*")[0]}
		rescue ::Exception => e
			raise ::XMLRPC::FaultException.new(500, "failed to generate: #{e.message}")
		end
	end

	def _run_post(mod, opts)
		Msf::Simple::Post.run_simple(mod, {
			'RunAsJob' => true,
			'Options'  => opts
		})
		{"result" => "success"}
	end
end
end
end

