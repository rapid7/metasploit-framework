
require 'msf/core'

lib = File.join(Msf::Config.install_root, "test", "lib")
require 'module_test'

class MetasploitModule < Msf::Post

  include Msf::ModuleTest::PostTest
  include Msf::Post::Windows::Railgun

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Railgun API Tests',
      'Description'   => %q{ This module will test railgun api functions },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Spencer McIntyre' ],
      'Platform'      => [ 'linux', 'osx', 'windows' ]
    ))
  end

  def test_api_function_calls_libc
    return unless session.platform == 'linux' || session.platform == 'osx'

    buffer = nil
    buffer_size = 128
    buffer_value = nil
    it "Should include error information in the results" do
      ret = true
      result = session.railgun.libc.malloc(128)
      ret &&= result['GetLastError'] == 0
      ret &&= result['ErrorMessage'].is_a? String
    end

    it "Should support functions with no parameters" do
      ret = true
      result = session.railgun.libc.getpid()
      ret &&= result['GetLastError'] == 0
      ret &&= result['return'] == session.sys.process.getpid
    end

    it "Should support functions with literal parameters" do
      ret = true
      result = session.railgun.libc.calloc(buffer_size, 1)
      ret &&= result['GetLastError'] == 0
      buffer = result['return']
      ret &&= buffer != 0
    end

    it "Should support functions with in/out/inout parameter types" do
      ret = true
      # first test in/out parameter types
      result = session.railgun.libc.inet_ntop('AF_INET', "\x0a\x00\x00\x01", 128, 128)
      ret &&= result['GetLastError'] == 0
      ret &&= result['return'] != 0
      ret &&= result['dst'][0...8] == '10.0.0.1'
      # then test the inout parameter type
      result = session.railgun.libc.strcat("meta\x00\x00\x00\x00\x00\x00\x00", 'sploit')
      ret &&= result['GetLastError'] == 0
      ret &&= result['return'] != 0
      ret &&= result['to'] == 'metasploit'
    end

    it "Should support calling multiple functions at once" do
      ret = true
      multi_rail = [
        ['libc', 'getpid', []],
        ['libc', 'strcat', ["meta\x00\x00\x00\x00\x00\x00\x00", 'sploit']]
      ]
      results = session.railgun.multi(multi_rail)
      ret &&= results.length == multi_rail.length
      ret &&= results[0]['return'] == session.sys.process.getpid
      ret &&= results[1]['to'] == 'metasploit'
    end

    it "Should support writing memory" do
      ret = true
      buffer_value = Rex::Text.rand_text_alphanumeric(buffer_size)
      ret &&= session.railgun.memwrite(buffer, buffer_value)
    end

    it "Should support reading memory" do
      ret = true
      ret &&= session.railgun.memread(buffer, buffer_size) == buffer_value
    end

    session.railgun.libc.free(buffer)
  end

  def test_api_function_calls_windows
    return unless session.platform == 'windows'
    it "Should include error information in the results" do
      ret = true
      result = session.railgun.kernel32.GetCurrentProcess()
      ret &&= result['GetLastError'] == 0
      ret &&= result['ErrorMessage'].is_a? String
    end

    it "Should support functions with no parameters" do
      ret = true
      result = session.railgun.kernel32.GetCurrentThread()
      ret &&= result['GetLastError'] == 0
      ret &&= result['return'] != 0
    end

    it "Should support functions with literal parameters" do
      ret = true
      result = session.railgun.kernel32.Sleep(50)
      ret &&= result['GetLastError'] == 0
    end

    it "Should support functions with in/out/inout parameter types" do
      ret = true
      # DnsHostnameToComputerNameA is ideal because it uses all 3 types see:
      # https://msdn.microsoft.com/en-us/library/windows/desktop/ms724244(v=vs.85).aspx
      result = session.railgun.kernel32.DnsHostnameToComputerNameA('localhost', 64, 64)
      ret &&= result['GetLastError'] == 0
      ret &&= result['ComputerName'].is_a? String
      ret &&= result['nSize'].to_i == result['ComputerName'].length
    end

    it "Should support calling multiple functions at once" do
      ret = true
      multi_rail = [
        ['kernel32', 'LoadLibraryA', ['kernel32.dll']],
        ['kernel32', 'GetModuleHandleA', ['kernel32.dll']],
        ['kernel32', 'GetCurrentProcessId', []]
      ]
      results = session.railgun.multi(multi_rail)
      ret &&= results.length == multi_rail.length
      results.each do |result|
        ret &&= result['GetLastError'] == 0
        ret &&= result['return'] != 0
      end

      # LoadLibraryA('kernel32.dll') == GetModuleHandleA('kernel32.dll')
      ret &&= results[0]['return'] == results[1]['return']
      ret &&= results[2]['return'] == session.sys.process.getpid
    end

    it "Should support writing memory" do
      ret = true
      result = session.railgun.kernel32.GetProcessHeap()
      ret &&= result['GetLastError'] == 0
      ret &&= result['return'] != 0
      return false unless ret

      buffer_size = 32
      handle = result['return']
      result = session.railgun.kernel32.HeapAlloc(handle, 0, buffer_size)
      ret &&= result['GetLastError'] == 0
      ret &&= result['return'] != 0
      return false unless ret

      buffer_value = Rex::Text.rand_text_alphanumeric(buffer_size)
      buffer = result['return']
      ret &&= session.railgun.memwrite(buffer, buffer_value)
      ret &&= session.railgun.memread(buffer, buffer_size) == buffer_value

      session.railgun.kernel32.HeapFree(handle, 0, buffer)
      ret
    end

    it "Should support reading memory" do
      ret = true
      result = session.railgun.kernel32.GetModuleHandleA('kernel32')
      ret &&= result['GetLastError'] == 0
      ret &&= result['return'] != 0
      return false unless ret

      handle = result['return']
      mz_header = session.railgun.memread(handle, 4)
      ret &&= mz_header == "MZ\x90\x00"
    end
  end
end
