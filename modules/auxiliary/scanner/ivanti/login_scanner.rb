require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute
  include Msf::Exploit::Remote::HttpClient

  def initialize; end
end
