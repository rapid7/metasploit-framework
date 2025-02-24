# -*- coding: binary -*-

module Msf
  module Exploit::Remote::Asterisk
    include Msf::Exploit::Remote::Tcp
    include Msf::Auxiliary::Report

    def initialize(info = {})
      super

      register_options(
        [
          Opt::RPORT(5038),
          OptString.new('USERNAME', [true, 'The username for Asterisk Access', '']),
          OptString.new('PASSWORD', [true, 'The password for the specified username', '']),
        ], self.class
      )
    end

    #
    # Handler for sending AMI commands
    #
    # @param cmd [String] command to send
    #
    # @return [String] response from the server
    def send_command(cmd = '')
      sock.put cmd

      res = ''
      timeout = 15
      Timeout.timeout(timeout) do
        res << sock.get_once while res !~ /\r?\n\r?\n/
      end

      res
    rescue Timeout::Error
      print_error "Timeout (#{timeout} seconds)"
    rescue StandardError => e
      print_error e.message
    end

    #
    # Attempt to get the asterisk version number
    #
    #
    # @return [Gem::Version] version response from the server. False on error
    def get_asterisk_version
      vprint_status 'Checking Asterisk version'

      req = "action: command\r\n"
      req << "command: core show version\r\n"
      req << "\r\n"
      res = send_command req

      return false if res =~ /Response: Error/

      # example output
      # Response: Success
      # Message: Command output follows
      # Output: Asterisk 19.8.0 built by mockbuild @ jenkins7 on a x86_64 running Linux on 2023-01-16 07:07:49 UTC

      # https://rubular.com/r/e2LvocVBeKaiVo
      if res =~ /^Output: Asterisk (.*?) built/
        return ::Regexp.last_match(1)
      end

      false
    end

    #
    # Handler for logging in to AMI
    #
    # @param username [String] username of the user
    # @param password [String] password of the user
    #
    # @return [Boolean] true on success, false on failure
    def login(username, password)
      vprint_status "Authenticating as '#{username}'"

      req = "action: login\r\n"
      req << "username: #{username}\r\n"
      req << "secret: #{password}\r\n"
      req << "events: off\r\n"
      req << "\r\n"
      res = send_command req

      return false unless res =~ /Response: Success/

      report_cred user: username,
                  password: password,
                  proof: 'Response: Success'

      report_service host: rhost,
                     port: rport,
                     proto: 'tcp',
                     name: 'asterisk'
      true
    end

    def report_cred(opts)
      service_data = {
        address: rhost,
        port: rport,
        service_name: 'asterisk_manager',
        protocol: 'tcp',
        workspace_id: myworkspace_id
      }

      credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        username: opts[:username],
        private_data: opts[:password],
        private_type: :password
      }.merge service_data

      login_data = {
        core: create_credential(credential_data),
        status: Metasploit::Model::Login::Status::UNTRIED,
        proof: opts[:proof]
      }.merge service_data

      create_credential_login login_data
    end
  end
end
