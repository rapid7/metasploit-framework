##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

##
# Author: Robin Wood <robin@digininja.org> <http://www.digininja.org>
# Version: 0.1
#
# This module will search the specified MSSQL server for
# 'interesting' columns and data
#
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL
  include Msf::OptionalSession::MSSQL

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microsoft SQL Server Interesting Data Finder',
        'Description' => %q{
          This module will search the specified MSSQL server for
          'interesting' columns and data.

          This module has been tested against the latest SQL Server 2019 docker container image (22/04/2021).
        },
        'Author' => [ 'Robin Wood <robin[at]digininja.org>' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'http://www.digininja.org/metasploit/mssql_idf.php' ],
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('NAMES', [ true, 'Pipe separated list of column names', 'passw|bank|credit|card']),
      ]
    )
  end

  def print_with_underline(str)
    print_line(str)
    print_line('=' * str.length)
  end

  def run
    headings = [
      ['Database', 'Schema', 'Table', 'Column', 'Data Type', 'Row Count']
    ]

    sql = ''
    sql += 'DECLARE @dbname nvarchar(255), @id int, @sql varchar (4000); '
    sql += 'DECLARE table_cursor CURSOR FOR SELECT name FROM sys.databases '
    sql += 'OPEN table_cursor '
    sql += 'FETCH NEXT FROM table_cursor INTO @dbname '
    sql += 'WHILE (@@FETCH_STATUS = 0) '
    sql += 'BEGIN '
    sql += "SET @sql = 'select ';"
    sql += "SET @sql = @sql + ' ''' + @dbname + ''' as ''Database'', ';"
    sql += "SET @sql = @sql + 'sys.schemas.name as ''Schema'', ';"
    sql += "SET @sql = @sql + 'sys.objects.name as ''Table'', ';"
    sql += "SET @sql = @sql + 'sys.columns.name as ''Column'', ';"
    sql += "SET @sql = @sql + 'sys.types.name as ''Column Type'' ';"
    sql += "SET @sql = @sql + 'from ' + @dbname + '.sys.columns ';"
    sql += "SET @sql = @sql + 'inner join ' + @dbname + '.sys.objects on sys.objects.object_id = sys.columns.object_id ';"
    sql += "SET @sql = @sql + 'inner join ' + @dbname + '.sys.types on sys.types.user_type_id = sys.columns.user_type_id ';"
    sql += "SET @sql = @sql + 'inner join ' + @dbname + '.sys.schemas on sys.schemas.schema_id = sys.objects.schema_id ';"

    list = datastore['Names']
    where = "SET @sql = @sql + ' WHERE ("
    list.split(/\|/).each do |val|
      where += " lower(sys.columns.name) like ''%" + val + "%'' OR "
    end

    where.slice!(-3, 4)

    where += ") ';"

    sql += where

    sql += "SET @sql = @sql + 'and sys.objects.type=''U'';';"
    sql += 'EXEC (@sql);'
    sql += 'FETCH NEXT FROM table_cursor INTO @dbname '
    sql += 'END '
    sql += 'CLOSE table_cursor '
    sql += 'DEALLOCATE table_cursor '

    begin
      if session
        set_mssql_session(session.client)
      else
        unless mssql_login_datastore
          print_error('Login failed')
          return
        end
      end
      result = mssql_query(sql, false)
    rescue Rex::ConnectionRefused => e
      print_error("Connection failed: #{e}")
      return
    end

    column_data = result[:rows]
    widths = [0, 0, 0, 0, 0, 9]
    total_width = 0

    if result[:errors] && !result[:errors].empty?
      result[:errors].each do |err|
        print_error(err)
      end
    end

    if column_data.nil?
      print_error("No columns matched the pattern #{datastore['NAMES'].inspect}. Set the NAMES option to change this search pattern.")
      return
    end

    (column_data | headings).each do |row|
      0.upto(4) do |col|
        widths[col] = row[col].length if row[col].length > widths[col]
      end
    end

    widths.each do |a|
      total_width += a
    end

    print_line

    buffer = ''
    headings.each do |row|
      0.upto(5) do |col|
        buffer += row[col].ljust(widths[col] + 1)
      end
      print_line(buffer)
      print_line
      buffer = ''

      0.upto(5) do |col|
        buffer += print '=' * widths[col] + ' '
      end
      print_line(buffer)
      print_line
    end

    column_data.each do |row|
      count_sql = 'SELECT COUNT(*) AS count FROM '

      full_table = ''
      column_name = ''
      buffer = ''
      0.upto(4) do |col|
        full_table += row[col] + '.' if col < 3
        column_name = row[col] if col == 3
        buffer += row[col].ljust(widths[col] + 1)
      end
      full_table.slice!(-1, 1)
      count_sql += full_table

      result = mssql_query(count_sql, false) if mssql_login_datastore

      count_data = result[:rows]
      row_count = count_data[0][0]

      buffer += row_count.to_s
      print_line(buffer)
      print_line
    end

    print_line
    disconnect
  end
end
