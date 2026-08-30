# -*- coding: binary -*-

module Msf
  module Exploit::Local::Ansible
    def initialize(info = {})
      super

      register_advanced_options([
        Msf::OptString.new('ANSIBLE', [false, 'Ansible executable location', '']),
        Msf::OptString.new('ANSIBLEPLAYBOOK', [false, 'Ansible-playbook executable location', '']),
      ])
    end

    #
    # Uses the ansible command to ping hosts, returns an array of hashes
    #
    # @param ansible_exe [String] The name location of the ansible executable
    # @param hosts [String] The host string to use, defaults to 'all'
    # @return [Array, nil] containing a hash for each host. Each has consists of the
    #  following parameters: host, status, ping, changed.
    #  nil on error.
    #
    def ping_hosts(hosts = 'all')
      results = cmd_exec("#{ansible_exe} #{hosts} -m ping -o")
      # here's a regex with test: https://rubular.com/r/FMHhWx8QlVnidA
      regex = /(\S+)\s+\|\s+([A-Z]+)\s+=>\s+({.+})$/
      matches = results.scan(regex)

      hosts = []
      matches.each do |match|
        match[2] = JSON.parse(match[2])
        hosts << { 'host' => match[0], 'status' => match[1], 'ping' => match[2]['ping'], 'changed' => match[2]['changed'] }
      rescue JSON::ParserError
        return nil
      end
      hosts
    end

    #
    # Attempts to find the ansible-playbook executable. Verifies the
    # executable is executable by the user as well. Defaults to looking in
    # standard locations for Ubuntu and Docker:
    # ('/usr/local/bin/ansible-playbook', '/usr/bin/ansible-playbook')
    #
    # @param suggestion [String] The location of the ansible-playbook executable if
    #  not in a standard location
    # @return [String, nil] The executable location or nil if not found
    #
    def ansible_playbook_exe(suggestion = datastore['ANSIBLEPLAYBOOK'])
      return @ansible_playbook if @ansible_playbook

      [suggestion, '/usr/local/bin/ansible-playbook', '/usr/bin/ansible-playbook'].each do |exec|
        next if exec.blank?
        next unless executable?(exec)

        @ansible_playbook = exec
        return @ansible_playbook
      end
      @ansible_playbook
    end

    #
    # Attempts to find the ansible executable. Verifies the
    # executable is executable by the user as well. Defaults to looking in
    # standard locations for Ubuntu and Docker:
    # ('/usr/local/bin/ansible')
    #
    # @param suggestion [String] The location of the ansible executable if
    #  not in a standard location
    # @return [String, nil] The executable location or nil if not found
    #
    def ansible_exe(suggestion = datastore['ANSIBLE'])
      return @ansible if @ansible

      [suggestion, '/usr/local/bin/ansible'].each do |exec|
        next if exec.blank?
        next unless executable?(exec)

        @ansible = exec
        return @ansible
      end
      @ansible
    end
  end
end
