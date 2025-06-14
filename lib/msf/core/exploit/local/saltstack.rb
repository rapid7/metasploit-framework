require 'yaml'

module Msf
  module Exploit::Local::Saltstack
    #
    # lists minions using the salt-key command.
    #
    # @param salt_key_exe [String] The name location of the salt-key executable
    # @return [YAML] YAML document with the minions listed
    #
    def list_minions(salt_key_exe = 'salt-key')
      # pull minions from a master, returns hash of lists of the output
      print_status('Attempting to list minions')
      unless command_exists?(salt_key_exe)
        print_error('salt-key not present on system')
        return
      end

      begin
        out = cmd_exec(salt_key_exe, '-L --output=yaml', datastore['TIMEOUT'])
        vprint_status(out)
        minions = YAML.safe_load(out)
      rescue Psych::SyntaxError
        print_error('Unable to load salt-key -L data')
        return
      end

      store_path = store_loot('saltstack_minions', 'application/x-yaml', session, minions.to_yaml, 'minions.yaml', 'SaltStack Salt salt-key list')
      print_good("#{peer} - minion file successfully retrieved and saved to #{store_path}")
      minions
    end
  end
end
