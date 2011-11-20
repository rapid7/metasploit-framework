##
# $Id: mssql_FindandSampleData.rb 2011-11-15 nullbind $
##

##
#  Credits: 
#  Thank you Dijininja for your original IDF 
#  module.  Also, thank you  humble-desser and DarkOperator
#  helping me work through a few critical issues.
##

## 
#  Use Case:
#  This script will search through all of the non-default 
#  databases on the SQL Server for columns that match the 
#  keywords defined in the TSQL KEYWORDS option. If column 
#  names are found that match the defined keywords and 
#  data is present in the associated tables, the script 
#  will select a sample of the records from each 
#  of the affected tables.  The sample size is determined
#  by the SAMPLESIZE option.  Also, the results can be written to a
#  CSV file if the OUTPUT is set to "yes" and an OUTPUTPATH option is set.
#
#  This script is valuable for gathering evidence during PCI
#  penetration tests and could even be used during the PCI 
#  data dicovery process.
#
#  Important note: This script only works on SQL Server 2005 and 2008
##

require 'msf/core'


class Metasploit3 < Msf::Auxiliary

	include Msf::Exploit::Remote::MSSQL
	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Microsoft SQL Server - Find and Sample Data',
			'Description'    => %q{This script will search through all of the non-default databases 
			on the SQL Server for columns that match the keywords defined in the TSQL KEYWORDS 
			option. If column names are found that match the defined keywords and data is present 
			in the associated tables, the script will select a sample of the records from each of 
			the affected tables.  The sample size is determined by the SAMPLESIZE option.  Also, 
			the results can be written to a CSV file if the OUTPUT is set to "yes" and the 
			OUTPUTPATH option is set.
			},
			'Author'         => [ 'Scot Sutherland (nullbind) <scott.sutherland@netspi.com>' ],
			'Version'        => '$Revision: 12196 $',
			'License'        => MSF_LICENSE,
			'References'     => [[ 'URL', 'http://www.netspi.com/blog/author/ssutherland/' ]],
			'Targets'        => [[ 'MSSQL 2005', { 'ver' => 2005 }]]
		))

		register_options(
			[
				OptString.new('KEYWORDS', [ true, 'Keywords to search for','passw|credit|card']),
				OptString.new('SAMPLESIZE', [ true, 'Number of rows to sample',  '1']),
				OptString.new('OUTPUT', [ false, 'Generate CSV file from search results',  'no']),
				OptString.new('OUTPUTPATH', [ false, 'File output path (C:\\\filename.csv)',  '']),
			], self.class)
	end

	def print_with_underline(str)
		print_line(str)
		print_line("=" * str.length)
	end

	def run_host(ip)
	
		#SETUP PRETTY OPTION VARIABLES FOR LATER USE		
		opt_sample = datastore['SAMPLESIZE']
		opt_ouput = datastore['OUTPUT']
		opt_outputpath = datastore['OUTPUTPATH']
		opt_keywords = datastore['KEYWORDS']
	
		#DEFINED HEADER TEXT
		headings = [
			["Server","Database", "Schema", "Table", "Column", "Data Type", "Sample Data","Row Count"]
		]

		#DEFINE SEARCH QUERY AS VARIABLE
		sql = "
		-- CHECK IF VERSION IS COMPATABLE > than 2000
		IF (SELECT SUBSTRING(CAST(SERVERPROPERTY('ProductVersion') as VARCHAR), 1, 
		CHARINDEX('.',cast(SERVERPROPERTY('ProductVersion') as VARCHAR),1)-1)) > 8
		BEGIN
			
			-- TURN OFF ROW COUNT
			SET NOCOUNT ON;			
			--------------------------------------------------
			-- SETUP UP SAMPLE SIZE
			--------------------------------------------------
			DECLARE @SAMPLE_COUNT varchar(MAX);
			SET @SAMPLE_COUNT = #{opt_sample};

			--------------------------------------------------
			-- SETUP KEYWORDS TO SEARCH
			--------------------------------------------------
			DECLARE @KEYWORDS varchar(MAX);	
			SET @KEYWORDS = '#{opt_keywords}|';
			
			--------------------------------------------------
			--SETUP WHERE STATEMENT CONTAINING KEYWORDS
			--------------------------------------------------
			DECLARE @SEARCH_TERMS varchar(MAX);	
			SET @SEARCH_TERMS = ''; -- Leave this blank

			-- START WHILE LOOP HERE -- BEGIN TO ITTERATE THROUGH KEYWORDS
				
				WHILE LEN(@KEYWORDS) > 0 
					BEGIN
						--SET VARIABLES UP FOR PARSING PROCESS
						DECLARE @change int
						DECLARE @keyword varchar(MAX)
							
						--SET KEYWORD CHANGE TRACKER
						SELECT @change = CHARINDEX('|',@KEYWORDS); 		
							
						--PARSE KEYWORD	
						SELECT @keyword = SUBSTRING(@KEYWORDS,0,@change) ;
							
						-- PROCESS KEYWORD AND GENERATE WHERE CLAUSE FOR IT	
						SELECT @SEARCH_TERMS = 'LOWER(COLUMN_NAME) like ''%'+@keyword+'%'' or '+@SEARCH_TERMS

						-- REMOVE PROCESSED KEYWORD
						SET @KEYWORDS = SUBSTRING(@KEYWORDS,@change+1,LEN(@KEYWORDS));
						
					END			    		
				-- REMOVE UNEEDED 					
				SELECT @SEARCH_TERMS = SUBSTRING(@SEARCH_TERMS,0,LEN(@SEARCH_TERMS)-2);

			--------------------------------------------------
			-- CREATE GLOBAL TEMP TABLES
			--------------------------------------------------
			USE master;

			IF OBJECT_ID('tempdb..##mytable') IS NOT NULL DROP TABLE ##mytable;
			IF OBJECT_ID('tempdb..##mytable') IS NULL 
			BEGIN 
				CREATE TABLE ##mytable (
					server_name varchar(MAX),
					database_name varchar(MAX),
					table_schema varchar(MAX),
					table_name varchar(MAX),		
					column_name varchar(MAX),
					column_data_type varchar(MAX)
				) 
			END

			IF OBJECT_ID('tempdb..##mytable2') IS NOT NULL DROP TABLE ##mytable2;
			IF OBJECT_ID('tempdb..##mytable2') IS NULL 
			BEGIN 
				CREATE TABLE ##mytable2 (
					server_name varchar(MAX),
					database_name varchar(MAX),
					table_schema varchar(MAX),
					table_name varchar(MAX),
					column_name varchar(MAX),
					column_data_type varchar(MAX),
					column_value varchar(MAX),
					column_data_row_count varchar(MAX)
				) 
			END

			--------------------------------------------------
			-- CURSOR1
			-- ENUMERATE COLUMNS FROM EACH DATABASE THAT 
			-- CONTAIN KEYWORD AND WRITE THEM TO A TEMP TABLE 
			--------------------------------------------------

			-- SETUP SOME VARIABLES FOR THE MYCURSOR1
			DECLARE @var1 varchar(max);
			DECLARE @var2 varchar(max);

			--------------------------------------------------------------------
			-- CHECK IF ANY NON-DEFAULT DATABASE EXIST
			--------------------------------------------------------------------
			IF (SELECT count(*) 
			FROM master..sysdatabases 
			WHERE name NOT IN ('master','tempdb','model','msdb') 
			and HAS_DBACCESS(name) <> 0) <> 0 
			BEGIN
				DECLARE MY_CURSOR1 CURSOR
				FOR

				SELECT name FROM master..sysdatabases 
				WHERE name NOT IN ('master','tempdb','model','msdb') 
				and HAS_DBACCESS(name) <> 0;

				OPEN MY_CURSOR1
				FETCH NEXT FROM MY_CURSOR1 INTO @var1
				WHILE @@FETCH_STATUS = 0   
				BEGIN  	
				---------------------------------------------------
				-- SEARCH FOR KEYWORDS/INSERT RESULTS INTO MYTABLE			
				---------------------------------------------------
				SET @var2 = ' 	
				INSERT INTO ##mytable
				SELECT @@SERVERNAME as SERVER_NAME,
				TABLE_CATALOG as DATABASE_NAME,
				TABLE_SCHEMA,
				TABLE_NAME,
				COLUMN_NAME,
				DATA_TYPE
				FROM ['+@var1+'].[INFORMATION_SCHEMA].[COLUMNS] WHERE '
				
				--APPEND KEYWORDS TO QUERY
				DECLARE @fullquery VARCHAR(MAX);
				SET @fullquery = @var2+@SEARCH_TERMS;				
					
				EXEC(@fullquery);	
				FETCH NEXT FROM MY_CURSOR1 INTO @var1

				END   
				CLOSE MY_CURSOR1
				DEALLOCATE MY_CURSOR1
				-------------------------------------------------
				-- CURSOR2
				-- TAKE A X RECORD SAMPLE FROM EACH OF THE COLUMNS
				-- THAT MATCH THE DEFINED KEYWORDS
				-- NOTE: THIS WILL NOT SAMPLE EMPTY TABLES
				-------------------------------------------------
				
				IF (SELECT COUNT(*) FROM ##mytable) < 1
					BEGIN	
						SELECT 'No columns where found that match the defined keywords.' as Message;
					END
				ELSE
					BEGIN			
						DECLARE @var_server varchar(max)
						DECLARE @var_database varchar(max)
						DECLARE @var_table varchar(max)
						DECLARE @var_table_schema varchar(max)
						DECLARE @var_column_data_type varchar(max)
						DECLARE @var_column varchar(max)
						DECLARE @myquery varchar(max)
						DECLARE @var_column_data_row_count varchar(MAX)
						
						DECLARE MY_CURSOR2 CURSOR
						FOR
						SELECT server_name,database_name,table_schema,table_name,column_name,column_data_type
						FROM ##mytable

							OPEN MY_CURSOR2
							FETCH NEXT FROM MY_CURSOR2 INTO @var_server,
							@var_database,
							@var_table_schema,
							@var_table,
							@var_column,
							@var_column_data_type
							WHILE @@FETCH_STATUS = 0   
							BEGIN  
							----------------------------------------------------------------------
							-- ADD AFFECTED SERVER/SCHEMA/TABLE/COLUMN/DATATYPE/SAMPLE DATA TO MYTABLE2
							----------------------------------------------------------------------
							-- GET COUNT
							DECLARE @mycount_query as varchar(MAX);
							DECLARE @mycount as varchar(MAX);

							-- CREATE TEMP TABLE TO GET THE COLUMN DATA ROW COUNT
							IF OBJECT_ID('tempdb..#mycount') IS NOT NULL DROP TABLE #mycount
							CREATE TABLE #mycount(mycount VARCHAR(MAX));
							
							-- SETUP AND EXECUTE THE COLUMN DATA ROW COUNT QUERY
							SET @mycount_query = 'INSERT INTO #mycount SELECT DISTINCT 
												COUNT('+@var_column+') FROM '+@var_database+'.
												'+@var_table_schema+'.'+@var_table;
							EXEC(@mycount_query);

							-- SET THE COLUMN DATA ROW COUNT
							SELECT @mycount = mycount FROM #mycount;		
							
							-- REMOVE TEMP TABLE
							IF OBJECT_ID('tempdb..#mycount') IS NOT NULL DROP TABLE #mycount				

							SET @myquery = ' 	
							INSERT INTO ##mytable2 
										(server_name,
										database_name,
										table_schema,
										table_name,
										column_name,
										column_data_type,
										column_value,
										column_data_row_count) 
							SELECT TOP '+@SAMPLE_COUNT+' ('''+@var_server+''') as server_name,
										('''+@var_database+''') as database_name,
										('''+@var_table_schema+''') as table_schema,
										('''+@var_table+''') as table_name,
										('''+@var_column+''') as comlumn_name,
										('''+@var_column_data_type+''') as column_data_type,
										'+@var_column+','+@mycount+' as column_data_row_count 
							FROM ['+@var_database+'].['+@var_table_schema++'].['+@var_table+'] 
							WHERE '+@var_column+' IS NOT NULL;
							'	
							EXEC(@myquery);

							FETCH NEXT FROM MY_CURSOR2 INTO 
										@var_server,
										@var_database,
										@var_table_schema,
										@var_table,@var_column,
										@var_column_data_type
							END   
						CLOSE MY_CURSOR2
						DEALLOCATE MY_CURSOR2

						-----------------------------------
						-- SELECT THE RESULTS OF THE SEARCH
						-----------------------------------
						IF (SELECT @SAMPLE_COUNT)= 1
							BEGIN
								SELECT DISTINCT cast(server_name as CHAR) as server_name,
								cast(database_name as char) as database_name,
								cast(table_schema as char) as table_schema,
								cast(table_name as char) as table_schema,
								cast(column_name as char) as column_name,
								cast(column_data_type as char) as column_data_type,
								cast(column_value as char) as column_data_sample,
								cast(column_data_row_count as char) as column_data_row_count FROM ##mytable2 								
							END	
						ELSE
							BEGIN
								SELECT DISTINCT cast(server_name as CHAR) as server_name,
								cast(database_name as char) as database_name,
								cast(table_schema as char) as table_schema,
								cast(table_name as char) as table_schema,
								cast(column_name as char) as column_name,
								cast(column_data_type as char) as column_data_type,
								cast(column_value as char) as column_data_sample,
								cast(column_data_row_count as char) as column_data_row_count FROM ##mytable2 							
							END
					END
			-----------------------------------
			-- REMOVE GLOBAL TEMP TABLES
			-----------------------------------
			IF OBJECT_ID('tempdb..##mytable') IS NOT NULL DROP TABLE ##mytable;
			IF OBJECT_ID('tempdb..##mytable2') IS NOT NULL DROP TABLE ##mytable2;
				
			END
			ELSE
			BEGIN
				----------------------------------------------------------------------
				-- RETURN ERROR MESSAGES IF THERE ARE NOT DATABASES TO ACCESS
				----------------------------------------------------------------------
				IF (SELECT count(*) FROM master..sysdatabases 
				WHERE name NOT IN ('master','tempdb','model','msdb')) < 1	
					SELECT 'No non-default databases exist to search.' as Message;
				ELSE
					SELECT 'Non-default databases exist, 
					but the current user does not have 
					the privileges to access them.' as Message;				
				END
		END
		else
		BEGIN
			SELECT 'This module only works on SQL Server 2005 and above.';
		END
		
		SET NOCOUNT OFF;"
		
		#STATUSING
		print_line(" ")
		print_line("[*] STATUS: Attempting to connect to the SQL Server at #{rhost}:#{rport}...")
		
		#CREATE DATABASE CONNECTION AND SUBMIT QUERY WITH ERROR HANDLING
		begin
			result = mssql_query(sql, false) if mssql_login_datastore
			column_data = result[:rows]
			print_line("[*] STATUS: Connected to #{rhost}:#{rport} successfully.")			
			rescue
			print_line("[-] ERROR : Connection to #{rhost}:#{rport} failed.")
			return
		end

		#STATUSING		
		print_line("[*] STATUS: Attempting to retrieve data ...")
				
		if (column_data.count < 7) 
			#Return error from SQL server
			column_data.each { |row|
				print_line("[*] STATUS: #{row.to_s.gsub("[","").gsub("]","").gsub("\"","")}")
			}
		return
		else
			#Setup column width for standard query results
			column_data.each { |row|
				0.upto(7) { |col|
					row[col] = row[col].strip.to_s	
					}		
			}
			print_line(" ")
		end
						
		#SETUP ROW WIDTHS
		widths = [0, 0, 0, 0, 0, 0, 0, 0]		
		(column_data|headings).each { |row|
			0.upto(7) { |col|				
				widths[col] = row[col].to_s.length if row[col].to_s.length > widths[col] 
			}
		}		
		
		#PRINT HEADERS
		buffer1 = ""
		buffer2 = ""
		headings.each { |row|
			0.upto(7) { |col|
				buffer1 += row[col].ljust(widths[col] + 1)
				buffer2 += row[col]+ ","
			}
			print_line(buffer1)	
			buffer2 = buffer2.chomp(",")+ "\n"	 
			File.open(opt_outputpath, 'ab') do |myfile| myfile.print(buffer2) 		
			end if (opt_ouput.downcase == "yes" and opt_outputpath.downcase != "")			
		}
		
		#PRINT DIVIDERS
		buffer1 = ""
		buffer2 = ""
		headings.each { |row|
			0.upto(7) { |col|
				divider = "=" * widths[col] + " "
				buffer1 += divider.ljust(widths[col] + 1)
			}
			print_line(buffer1)				
		}

		#PRINT DATA
		buffer1 = ""
		buffer2 = ""		
		print_line("")
		column_data.each { |row|
			0.upto(7) { |col|
				buffer1 += row[col].ljust(widths[col] + 1)
				buffer2 += row[col] + ","
			}
			print_line(buffer1)
			buffer2 = buffer2.chomp(",")+ "\n"	
			# Write query output to the defined file path 
			# Note: This will overwrite existing files
			File.open(opt_outputpath, 'ab') do |myfile| myfile.print(buffer2) 
			end if (opt_ouput.downcase == "yes" and opt_outputpath.downcase != "")
			buffer1 = ""
			buffer2 = ""
			print_line(buffer1)						
		}
		disconnect	
		
		#CHECK IF QUERY OUTPUT WAS WRITTEN TO THE FILE
		if File.exist?(opt_outputpath) 
			print_line("[*] The query output from #{rhost} has been written to: #{opt_outputpath}")
		else
			print_line("[*] The query output from #{rhost} was NOT written to a file.")
		end
		

	end
end