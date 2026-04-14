
require 'metasploit/framework/compiler/windows'
module Msf::Obfuscation::ExeTemplate
  def self.exe_template_compile(framework, opts)
    template_path = framework.datastore['EXE::Obfuscation::Path'] || File.join(Msf::Config.data_directory, 'templates/src/pe/exe')
    template = framework.datastore['EXE::Obfuscation::Template'] || "template.c.erb"
    # if template is a erb file, render it with erb
    if File.extname(template) == '.erb'
      template = ERB.new(File.read(File.join(template_path, template))).result(binding)
    end
    template_file = File.join(template_path, template)
    arch = opts[:arch].first if opts[:arch].kind_of? Array
    metasm_cpu = arch == ARCH_X64 ? Metasm::X64.new : Metasm::Ia32.new
    windows_compiler_options = {
      :type => :exe,
      :cpu => metasm_cpu,
      :weight => 100
    }
    # binding.pry
    exe = Metasploit::Framework::Compiler::Windows.compile_random_c(File.read(template_file), windows_compiler_options)
    # If linux host, throw the exe in /tmp and return /tmp as path and the exe name.
    if File.exists?('/tmp/') && File.writable?('/tmp/')
      path = '/tmp/'
      out_file = File.join(path, "#{Rex::Text.rand_text_alpha(8)}.exe")
      File.write(out_file, exe, mode: 'wb')
      print_status("Compiled JIT obfuscation template to #{out_file}\n")
      return path, File.basename(out_file)
    else
      print_error("Template obfuscation currently works on Linux only with a writable /tmp directory.")
    end
    return nil, nil
  end

  def self.src_random_nested_functions(target_fname, depth=3, max_deadended_functions=5)
    prev_func = target_fname
    code = ""
    (1..depth).each do |i|
      deadend_functions_number = rand(1..max_deadended_functions)
      deadended_functions = [""]

      (1..deadend_functions_number).each do |j|
        dead_func_name = "#{Rex::Text.rand_text_alpha(16)}"
        code << "void #{dead_func_name}() {\n int i = #{rand(1..100)};\n}\n\n"
        deadended_functions << dead_func_name
      end
      
      func_name = "#{Rex::Text.rand_text_alpha(16)}"
      code << "void #{func_name}() {\n"
      prev_function_inserted = false
      deadend_functions_to_call = deadended_functions.sample(rand(1..deadended_functions.length))
      deadend_functions_to_call.each do |dead_func|
        if !prev_function_inserted && rand(0..1) == 1
          code << "  #{prev_func}();\n"
          prev_function_inserted = true
        end
        code << "  #{dead_func}();\n"
      end
      code << "  #{prev_func}();\n" unless prev_function_inserted
      code << "}\n\n"
      prev_func = func_name
    end
    code
  end
end