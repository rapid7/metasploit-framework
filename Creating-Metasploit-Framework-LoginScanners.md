So, you want to make a Login Scanner Module in Metasploit, eh? There are a few things you will need to know before you begin. This article will try to illustrate all the moving pieces involved in creating an effective bruteforce/login scanner module.

- [Credential objects](#credential-objects)
- [Result objects](#result-objects)
- [CredentialCollection](#credentialcollection)
- [LoginScanner Base](#loginscanner-base) 
  * [Attributes](#attributes)
  * [Methods](#methods)
  * [Constants](#constants)
- [Pulling it all Together in a module](#pulling-it-all-together-in-a-module)
  * [The Cred Collection](#the-cred-collection)
  * [Initialising the Scanner](#initialising-the-scanner)
  * [The scan block](#the-scan-block)
  * [ftp_login final view](#ftp_login-final-view)

### Credential Objects

Metasploit::Framework::Credential
(lib/metasploit/framework/credential.rb)

These objects represent the most basic concept of how we now think about Credentials.

- Public: The public part of a credential refers to the part that can be publicly known. In almost all cases this is the username.
- Private: The private part of the credential, this is the part that should be a secret. This currently represents: Password, SSH Key, NTLM Hash etc.
- Private Type: This defines what type of private credential is defined above
- Realm: This represents an authentication realm that the credential is valid for. This is a teritary part of the authentication process. Examples include: Active Directory Domain, Postgres Database etc.
- Realm Key: This defines what type of Realm the Realm Attribute represents
- Paired: This attribute is a boolean value that sets whether the Credential must have both a public and private to be valid


All LoginScanners use Credential objects as the basis for their attempts.

### Result Objects

Metasploit::Framework::LoginScanner::Result
(lib/metasploit/framework/login_scanner/result.rb)

These are the objects yielded by the scan! method on each LoginScanner.  They contain:

- Access Level: an optional Access Level which can describe the level of access granted by the login attempt. 
- Credential : the Credential object that achieved that result
- Proof: an optional proof string to show why we think the result is valid
- Status: The status of the login attempt. These values come from Metasploit::model::Login::Status , examples include "Incorrect", "Unable to Connect", "Untried" etc

### CredentialCollection

Metasploit::Framework::CredentialCollection
(lib/metasploit/framework/credential_collection.rb)

This class is used to take datastore options from a module and yield Credential objects from an each method. It takes wordlist files, as well as direct username and password options. It also takes options for username as pass and blank apssword. It can be passed in as the cred_details on the LoginScanner, and responds to #each and yields crafted Credentials.

Example (from modules/auxiliary/scanner/ftp/ftp_login.rb):

```ruby
cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: datastore['BLANK_PASSWORDS'],
        pass_file: datastore['PASS_FILE'],
        password: datastore['PASSWORD'],
        user_file: datastore['USER_FILE'],
        userpass_file: datastore['USERPASS_FILE'],
        username: datastore['USERNAME'],
        user_as_pass: datastore['USER_AS_PASS'],
        prepended_creds: anonymous_creds
    )
```



### LoginScanner Base

Metasploit::Framework::LoginScanner::Base
(lib/metasploit/framework/login_scanner/base.rb)


This is a Ruby Module that contains all the base behaviour for all LoginScanners. All LoginScanner classes should include this module.

The specs for this behaviour are kept in a shared example group. Specs for your LoginScanner should use the following syntax to include these tests:

```ruby 
it_behaves_like 'Metasploit::Framework::LoginScanner::Base', has_realm_key: false, has_default_realm: false
```
 Where has_realm_key and has_default_realm should be set according to whether your LoginScanner has those things. (More on this later)

LoginScanners always take a collection of Crednetials to try and one host and port. so each LoginScanner object attempts to login to only one specific service.

#### Attributes


 - connection_timeout: The time to wait for a connection to timeout
 - cred_details: An object that yeilds credentials on each (like credentialCollection or an Array)
 - host: The address for the target host
 - port: the port number for the target service
 - proxies: any proxies to use in the connection (some scanners might not support this)
 - stop_on_success: whether to stop trying after a successful login is found
 
#### Methods

 - each_credential : You will not have to worry much about this method, Be aware that it is there. It iterates through whatever is in cred_details, does some normalization and tries to make sure each Credential is properly setup for use by the given LoginScanner. It yields each Credential in a block.
 
 ```ruby
 def each_credential
            cred_details.each do |raw_cred|
              # This could be a Credential object, or a Credential Core, or an Attempt object
              # so make sure that whatever it is, we end up with a Credential.
              credential = raw_cred.to_credential

              if credential.realm.present? && self.class::REALM_KEY.present?
                credential.realm_key = self.class::REALM_KEY
                yield credential
              elsif credential.realm.blank? && self.class::REALM_KEY.present? && self.class::DEFAULT_REALM.present?
                credential.realm_key = self.class::REALM_KEY
                credential.realm     = self.class::DEFAULT_REALM
                yield credential
              elsif credential.realm.present? && self.class::REALM_KEY.blank?
                second_cred = credential.dup
                # Strip the realm off here, as we don't want it
                credential.realm = nil
                credential.realm_key = nil
                yield credential
                # Some services can take a domain in the username like this even though
                # they do not explicitly take a domain as part of the protocol.
                second_cred.public = "#{second_cred.realm}\\#{second_cred.public}"
                second_cred.realm = nil
                second_cred.realm_key = nil
                yield second_cred
              else
                yield credential
              end
            end
          end
```

 
 - set_sane_defaults: This method will be overridden by each specific Loginscanner. This is called at the end of the initializer and sets any sane defaults for attributes that have them and were not given a specific value in the initializer.
 
 ```ruby
 # This is a placeholder method. Each LoginScanner class
          # will override this with any sane defaults specific to
          # its own behaviour.
          # @abstract
          # @return [void]
          def set_sane_defaults
            self.connection_timeout = 30 if self.connection_timeout.nil?
          end
 ```
 
 -  attempt_login: This method is just a stub on the Base mixin. It will be ovverriden in each LoginScanner class to contain the logic to take one single Credential object and use it to make a login attempt against the target service. It returns a ::Metasploit::Framework::LoginScanner::Result object containing all the information about that attempt's result. For an example let's look at the attempt_login method from Metasploit::Framework::LoginScanner::FTP (lib/metasploit/framework/login_scanner/ftp.rb)
 
 ```ruby
 # (see Base#attempt_login)
        def attempt_login(credential)
          result_options = {
              credential: credential
          }

          begin
            success = connect_login(credential.public, credential.private)
          rescue ::EOFError,  Rex::AddressInUse, Rex::ConnectionError, Rex::ConnectionTimeout, ::Timeout::Error
            result_options[:status] = Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
            success = false
          end


          if success
            result_options[:status] = Metasploit::Model::Login::Status::SUCCESSFUL
          elsif !(result_options.has_key? :status)
            result_options[:status] = Metasploit::Model::Login::Status::INCORRECT
          end

          ::Metasploit::Framework::LoginScanner::Result.new(result_options)

        end
 ```
 
 - scan! : This method is the main one you will be concerned with. This method does several things. 
 	- It calls valid! which will check all of the validations on the class and raise an Metasploit::Framework::LoginScanner::Invalid if any of the Vlidations fail. This exception will contain all the errors messages for any failing validations.
 	- it keeps track of the connection error count, and will bail out if we have too many connection errors or too many in a row
 	- it runs throguh all of the credentials by calling each_credential with a block
 	- in that block it passes each credential to #attempt_login
 	- it yields the Result object into the block it is passed
 	- if stop_on_success is set it will also exit out early if it the reuslt was a success
 	
```ruby
# Attempt to login with every {Credential credential} in
          # {#cred_details}, by calling {#attempt_login} once for each.
          #
          # If a successful login is found for a user, no more attempts
          # will be made for that user.
          #
          # @yieldparam result [Result] The {Result} object for each attempt
          # @yieldreturn [void]
          # @return [void]
          def scan!
            valid!

            # Keep track of connection errors.
            # If we encounter too many, we will stop.
            consecutive_error_count = 0
            total_error_count = 0

            successful_users = Set.new

            each_credential do |credential|
              next if successful_users.include?(credential.public)

              result = attempt_login(credential)
              result.freeze

              yield result if block_given?

              if result.success?
                consecutive_error_count = 0
                break if stop_on_success
                successful_users << credential.public
              else
                if result.status == Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
                  consecutive_error_count += 1
                  total_error_count += 1
                  break if consecutive_error_count >= 3
                  break if total_error_count >= 10
                end
              end
            end
            nil
          end
```

#### Constants

Although not defined on Base, each LoginScanner has a series of Constants that can be defined on it to assist with critical behaviour.

 - DEFAULT_PORT: DEFAULT_PORT is a simple constant for use with set_sane_defaults. If the port isn't set by the user it will use DEFAULT_PORT. This is put in a constant so it can be quickly referenced from outside the scanner.

These next two Constants are used by the LoginScanner namespace method classes_for_services. This method invoked by `Metasploit::Framework::LoginScanner.classes_for_service(<Mdm::service>)` will actually return an array of LoginScanner classes that may be useful to try against that particular Service.
 - LIKELY_PORTS : This constant holds n array of port numbers that it would be likely useful to use this scanner against.
 - LIKELY_SERVICE_NAMES : like above except with strings for service names instead of port numbers.

 - PRIVATE_TYPES : This contains an array of symbols representing the different Private credential types it supports. It should always match the demodulize result for the Private class i.e :password, :ntlm_hash, :ssh_key

These constants are fore LoginScanners that have to deal with Realms such as AD domains or Database Names.

 - REALM_KEY: The type of Realm this scanner expects to deal with. Should always be a constants from metasploit::Model::Login::Status
 - DEFAULT_REALM: Some scanners have a default realm (like WORKSTATION for AD domain stuff). If a credential is given to a scanner that requires a realm, but the credential has no realm, this value will be added to the credential as the realm.
 
 - CAN_GET_SESSION: this should be either true or false as to whether we expect we could somehow get a session with a Credential found from this scanner.
 
 example1 ( Metasploit::Framework::LoginScanner::FTP)
 
 ```ruby
  DEFAULT_PORT         = 21
        LIKELY_PORTS         = [ DEFAULT_PORT, 2121 ]
        LIKELY_SERVICE_NAMES = [ 'ftp' ]
        PRIVATE_TYPES        = [ :password ]
        REALM_KEY           = nil
 ```
 
 example2 ( Metasploit::Framework::LoginScanner::SMB)
 
```ruby
  CAN_GET_SESSION      = true
        DEFAULT_REALM        = 'WORKSTATION'
        LIKELY_PORTS         = [ 139, 445 ]
        LIKELY_SERVICE_NAMES = [ "smb" ]
        PRIVATE_TYPES        = [ :password, :ntlm_hash ]
        REALM_KEY            = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
```


### Pulling it all Together in a module

So now you hopefully have a good diea of all the moving peices involved in creating a LoginScanner. The next step is using your brand new LoginScanner in an actual module. 

Let's look at the ftp_login module:

`def run_host(ip)`

Every Bruteforce/Login module should be a scanner and should use the run_host method which will run once for each RHOST.

#### The Cred Collection

```ruby
    cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: datastore['BLANK_PASSWORDS'],
        pass_file: datastore['PASS_FILE'],
        password: datastore['PASSWORD'],
        user_file: datastore['USER_FILE'],
        userpass_file: datastore['USERPASS_FILE'],
        username: datastore['USERNAME'],
        user_as_pass: datastore['USER_AS_PASS'],
        prepended_creds: anonymous_creds
    )

```
So here we see the CredentialCollection getting created using the datastore options. We pass in the options for Cred creation such as wordlists, raw usernames and passwords, whether to try the username as a password, and whether to try blank passwords. 

you'll also notice an option here called prepended_creds. FTP is one of the only module to make use of this, but it is generally available through the CredentialCollection. This option is an array of Metasploit::Framework::Credential objects that should be spit back by the collection before any others. FTP uses this to deal with testing for anon FTP access.

#### Initialising the Scanner

```ruby
scanner = Metasploit::Framework::LoginScanner::FTP.new(
        host: ip,
        port: rport,
        proxies: datastore['PROXIES'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        connection_timeout: 30
    )
```

Here we actually create our Scanner object. We set the IP and Port based on data the module already knows about. We can pull any user supplied proxy data from the datatstore. we also pull from the datastore whether to stop on a success for this service. the cred details object is populated by our Credentialcollection which will handle all the credential generation for us invisibly.

This gives us our scanner object, all configured and ready to go.


#### The scan block

```ruby
 scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
          module_fullname: self.fullname,
          workspace_id: myworkspace_id
      )
      if result.success?
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        print_good "#{ip}:#{rport} - LOGIN SUCCESSFUL: #{result.credential}"
      else
        invalidate_login(credential_data)
        print_status "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end

```

This is the real heart of the matter here. We call scan! on our scanner, and pass it a block. As we mentioned before, the scanner yields each attempt's Result object into that block. We check the result's status to see if it was successful or not.

The result object now as a .to_h method which returns a hash compatible with our credential creation methods. We take that hash and merge in our module specific information and workspace id.

In the case of a success we build some info hashes and call create_credential. This is a method found in the metasploit-credential gem under lib/metasploit/credential/creation.rb in a mixin called Metasploit::Credential::Creation. This mixin is included in the Report mixin, so if your module includes that mixin you'll get these methods for free.

create_credential creates a Metasploit::Credential::Core. We then take that core, the service data, and merge it with some additional data. This additional data includes the access level, the current time (to update last_attempted_at on the Metasploit::Credential::Login), the the status. 

Finally, for a success, we output the result to the console.

In the case of a failure, we call the invalidate_login method. This method also comes from the Creation mixin. This method looks to see if a Login object already exists for this credential:service pair. If it does, it updates the status to the status we got back from the scanner. This is primarily to account for Login objects created by things like Post modules that have an untried status.

#### ftp_login final view

Pulling it all together, we get a new ftp_login module that looks something like this:

```ruby
##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/ftp'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  def proto
    'ftp'
  end

  def initialize
    super(
      'Name'        => 'FTP Authentication Scanner',
      'Description' => %q{
        This module will test FTP logins on a range of machines and
        report successful logins.  If you have loaded a database plugin
        and connected to a database this module will record successful
        logins and hosts so you can track your access.
      },
      'Author'      => 'todb',
      'References'     =>
        [
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(21),
        OptBool.new('RECORD_GUEST', [ false, "Record anonymous/guest logins to the database", false])
      ], self.class)

    register_advanced_options(
      [
        OptBool.new('SINGLE_SESSION', [ false, 'Disconnect after every login attempt', false])
      ]
    )

    deregister_options('FTPUSER','FTPPASS') # Can use these, but should use 'username' and 'password'
    @accepts_all_logins = {}
  end


  def run_host(ip)
    print_status("#{ip}:#{rport} - Starting FTP login sweep")

    cred_collection = Metasploit::Framework::CredentialCollection.new(
        blank_passwords: datastore['BLANK_PASSWORDS'],
        pass_file: datastore['PASS_FILE'],
        password: datastore['PASSWORD'],
        user_file: datastore['USER_FILE'],
        userpass_file: datastore['USERPASS_FILE'],
        username: datastore['USERNAME'],
        user_as_pass: datastore['USER_AS_PASS'],
        prepended_creds: anonymous_creds
    )

    scanner = Metasploit::Framework::LoginScanner::FTP.new(
        host: ip,
        port: rport,
        proxies: datastore['PROXIES'],
        cred_details: cred_collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        connection_timeout: 30
    )

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
          module_fullname: self.fullname,
          workspace_id: myworkspace_id
      )
      if result.success?
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        print_good "#{ip}:#{rport} - LOGIN SUCCESSFUL: #{result.credential}"
      else
        invalidate_login(credential_data)
        print_status "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
      end
    end

  end


  # Always check for anonymous access by pretending to be a browser.
  def anonymous_creds
    anon_creds = [ ]
    if datastore['RECORD_GUEST']
      ['IEUser@', 'User@', 'mozilla@example.com', 'chrome@example.com' ].each do |password|
        anon_creds << Metasploit::Framework::Credential.new(public: 'anonymous', private: password)
      end
    end
    anon_creds
  end

  def test_ftp_access(user,scanner)
    dir = Rex::Text.rand_text_alpha(8)
    write_check = scanner.send_cmd(['MKD', dir], true)
    if write_check and write_check =~ /^2/
      scanner.send_cmd(['RMD',dir], true)
      print_status("#{rhost}:#{rport} - User '#{user}' has READ/WRITE access")
      return 'Read/Write'
    else
      print_status("#{rhost}:#{rport} - User '#{user}' has READ access")
      return 'Read-only'
    end
  end


end


```