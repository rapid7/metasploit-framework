require 'erb'
require 'metasploit/framework/compiler/mingw'
require 'metasploit/framework/compiler/windows'
require 'metasploit/framework/compiler/custom'
module Msf::Obfluscation::ExeTemplate
  
  def self.exe_template_compile(framework, code, opts)
    template_path = framework.datastore['EXE::Template::Dynamic::CustomTemplate']
    template_path ||= File.join(Msf::Config.data_directory, 'templates','template_x64_windows_xor.erb')

    encryption_rounds = rand(2...10)
    xor_keys = encryption_rounds.times.map{ rand(256) }
      
    control_bytes = [rand(256)]

    for i in 0...encryption_rounds do
      control_bytes.append(control_bytes.last ^ xor_keys[i])
      code = code.bytes.map { |b| b ^ xor_keys[i] }.pack("C*")
    end

    code.prepend(control_bytes.last.chr)
    control_bytes = control_bytes.reverse
    control_bytes = control_bytes.drop(1)

    encrypted_payload_length = code.bytesize
    
    encrypted_payload = code.bytes.map { |b| "\\x%02x" % b }.join

    control_bytes = control_bytes.map { |b| "\\x%02x" % b }.join

    template = ERB.new(File.read(template_path))
    source_c = template.result(binding)

      
    return Metasploit::Framework::Compiler::Custom.compile_c(source_c, :exe)
    
    case framework.datastore['EXE::Template::Dynamic::Compiler']
    when nil, 'metasm'
      return Metasploit::Framework::Compiler::Windows.compile_c(source_c, :exe,Metasm::X86_64.new)
    when 'msfcompile'
      return Metasploit::Framework::Compiler::Custom.compile_c(source_c, :exe)
    else
      raise "Unknown compiler: #{opts['EXE::Template::Dynamic::Compiler']}"
    end

  end

end
