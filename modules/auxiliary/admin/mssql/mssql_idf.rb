##
# Author: Robin Wood <robin@digininja.org> <http://www.digininja.org>
# Version: 0.1
#
# This module will search the specified MSSQL server for
# 'interesting' columns and data
#
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::MSSQL

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft SQL Server - Interesting Data Finder',
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
			], self.class)
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


		# Add error handling here
		result = mssql_query(sql, false) if mssql_login_datastore
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

		print_line("")

		buffer = ""
		headings.each { |row|
			0.upto(5) { |col|
				buffer += row[col].ljust(widths[col] + 1)
			}
			print_line(buffer)
			print_line("")
			buffer = ""

			0.upto(5) { |col|
				buffer += print "=" * widths[col] + " "
			}
			print_line(buffer)
			print_line("")
		}

		table_data_sql = {}
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
			print_line("")

#			if row_count == 0
#				data_sql = nil
#				table_data_sql[full_table + "." + column_name] = nil
#			elsif row_count < 4
#				data_sql = "SELECT * from " + full_table
#				table_data_sql[full_table + "." + column_name] = data_sql
#			else
#				data_sql = "SELECT TOP 3 * from " + full_table
#
#				# or this will get top, middle and last rows
#
#				data_sql = "
#							with tmp as (select *,ROW_NUMBER() over (order by " + column_name + ") as rownumber from " + full_table + " )
#								select * from tmp where rownumber between 1 and 1;
#							with tmp as (select *,ROW_NUMBER() over (order by " + column_name + ") as rownumber from " + full_table + " )
#								select * from tmp where rownumber between " + (row_count / 2).to_s + " and " + (row_count / 2).to_s + ";
#							with tmp as (select *,ROW_NUMBER() over (order by " + column_name + ") as rownumber from " + full_table + " )
#								select * from tmp where rownumber between " + row_count.to_s + " and " + row_count.to_s + ";
#						"
#				table_data_sql[full_table + "." + column_name] = data_sql
#			end
		}

		print_line("")

		# The code from this point on is for dumping out some sample data however the MSSQL parser isn't working
		# correctly so the output is messed up. I'll finish implementing this once the bug is fixed.

#		print_line("")
#		print_with_underline("Sample Data")
#		print_line("")
#		table_data_sql.each_pair { |table, sql|
#			if !sql.nil?
#				print_with_underline table
#				result = mssql_query(sql, true) if mssql_login_datastore
#				#print_line result.inspect
#				result[:colnames].each { |row|
#					print row.ljust(20)
#				}
#			end
#		}
#
#			if !data_sql.nil?
#				result = mssql_query(data_sql, false) if mssql_login_datastore
#	#			print_line "INSPECT"
#	#			print_line result.keys.inspect
#	#			print_line result[:colnames].inspect
#		result[:colnames].each { |row|
#			print row.ljust(20)
#		}
#		print_line("")
#		result[:colnames].each { |row|
#			print "=" * 20 + " "
#		}
#		print_line("")
#
#				if !result[:rows].nil?
##				print_line data_sql
#					result[:rows].each { |acol|
#						acol.each { |aval|
#				#			print_line aval
#						}
#					}
#				end
#			end
		disconnect
	end
end
