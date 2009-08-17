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
	
	
	def info(token, mtype, mname)
		authenticate(token)
		
		m = _find_module(mtype,mname)
		res = {}

		res['name'] = m.name
		res['description'] = m.description
		res['license'] = m.license
		res['filepath'] = m.file_path
		res['version'] = m.version
		
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
		#m = @framework.exploits[mname]
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
		
		begin
		mod = _find_module(mtype,mname)
		case mtype
			when 'exploit'
				_run_exploit(mod, opts)
			when 'auxiliary'
				_run_auxiliary(mod, opts)
			when 'payload'
				_run_payload(mod, opts)
		end
		
		rescue ::Exception => e
			$stderr.puts "#{e.class} #{e} #{e.backtrace}"
		end
	end
	
protected

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
		
		begin
			res = Msf::Simple::Payload.generate_simple(mod, {
				'BadChars'    => badchars,
				'Encoder'     => opts['Encoder'],
				'NoComment'   => true,
				'Format'      => 'raw',
				'Options'     => opts	
			})

			{"result" => "success", "payload" => res.unpack("H*")[0]}	
		rescue ::Exception
			raise ::XMLRPC::FaultException.new(500, "failed to generate")
		end
	end
		
end
end
end
