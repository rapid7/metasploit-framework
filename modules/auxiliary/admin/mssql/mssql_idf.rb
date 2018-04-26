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

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft SQL Server Interesting Data Finder',
      'Description'    => %q{
        This module will search the specified MSSQL server for
        'interesting' columns and data.

        The module has been tested against SQL Server 2005 but it should also work on
        SQL Server 2008. The module will not work against SQL Server 2000 at this time,
        if you are interested in supporting this platform, please contact the author.
      },
      'Author'         => [ 'Robin Wood <robin[at]digininja.org>' ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          [ 'URL', 'http://www.digininja.org/metasploit/mssql_idf.php' ],
        ],
      'Targets'        =>
        [
          [ 'MSSQL 2005', { 'ver' => 2005 }	],
        ]
    ))

    register_options(
      [
        OptString.new('NAMES', [ true, 'Pipe separated list of column names',  'passw|bank|credit|card']),
      ])
  end

  def print_with_underline(str)
    print_line(str)
    print_line("=" * str.length)
  end

  def run
    headings = [
      ["Database", "Schema", "Table", "Column", "Data Type", "Row Count"]
    ]

    sql = ""
    sql += "DECLARE @dbname nvarchar(255), @id int, @sql varchar (4000); "
    sql += "DECLARE table_cursor CURSOR FOR SELECT name FROM sys.databases "
    sql += "OPEN table_cursor "
    sql += "FETCH NEXT FROM table_cursor INTO @dbname "
    sql += "WHILE (@@FETCH_STATUS = 0) "
    sql += "BEGIN "
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
    list.split(/\|/).each { |val|
      where += " lower(sys.columns.name) like ''%" + val + "%'' OR "
    }

    where.slice!(-3, 4)

    where += ") ';"

    sql += where

    sql += "SET @sql = @sql + 'and sys.objects.type=''U'';';"
    sql += "EXEC (@sql);"
    sql += "FETCH NEXT FROM table_cursor INTO @dbname "
    sql += "END "
    sql += "CLOSE table_cursor "
    sql += "DEALLOCATE table_cursor "

    begin
      if mssql_login_datastore
        result = mssql_query(sql, false)
        column_data = result[:rows]
      else
        print_error('Login failed')
        return
      end
    rescue Rex::ConnectionRefused => e
      print_error("Connection failed: #{e}")
      return
    end

    column_data = result[:rows]
    widths = [0, 0, 0, 0, 0, 9]
    total_width = 0

    (column_data|headings).each { |row|
      0.upto(4) { |col|
        widths[col] = row[col].length if row[col].length > widths[col]
      }
    }

    widths.each { |a|
      total_width += a
    }

    print_line

    buffer = ""
    headings.each { |row|
      0.upto(5) { |col|
        buffer += row[col].ljust(widths[col] + 1)
      }
      print_line(buffer)
      print_line
      buffer = ""

      0.upto(5) { |col|
        buffer += print "=" * widths[col] + " "
      }
      print_line(buffer)
      print_line
    }

    column_data.each { |row|
      count_sql = "SELECT COUNT(*) AS count FROM "

      full_table = ""
      column_name = ""
      buffer = ""
      0.upto(4) { |col|
        full_table += row[col] + '.' if col < 3
        column_name = row[col] if col == 3
        buffer += row[col].ljust(widths[col] + 1)
      }
      full_table.slice!(-1, 1)
      count_sql += full_table

      result = mssql_query(count_sql, false) if mssql_login_datastore

      count_data = result[:rows]
      row_count = count_data[0][0]

      buffer += row_count.to_s
      print_line(buffer)
      print_line
    }

    print_line
    disconnect
  end
end
