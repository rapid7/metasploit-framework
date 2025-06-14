##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'yaml'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MSSQL
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::OptionalSession::MSSQL

  def initialize
    super(
      'Name'           => 'MSSQL Schema Dump',
      'Description'    => %Q{
          This module attempts to extract the schema from a MSSQL Server
          Instance. It will disregard builtin and example DBs such
          as master, model, msdb, and tempdb. The module will create
          a note for each DB found, and store a YAML formatted output
          as loot for easy reading.
      },
      'Author'         => ['theLightCosine'],
      'License'        => MSF_LICENSE
    )

    register_options([
      OptBool.new('DISPLAY_RESULTS', [true, "Display the Results to the Screen", true])
    ])
  end

  def run_host(ip)
    if session
      set_mssql_session(session.client)
    else
      unless mssql_login_datastore
        print_error("#{datastore['RHOST']}:#{datastore['RPORT']} - Invalid SQL Server credentials")
        return
      end
    end

    # Grabs the Instance Name and Version of MSSQL(2k,2k5,2k8)
    instance_info = mssql_query(mssql_enumerate_servername())[:rows][0][0].split('\\')
    instancename = instance_info[1] || instance_info[0]

    print_status("Instance Name: #{instancename.inspect}")
    version = mssql_query(mssql_sql_info())[:rows][0][0]
    output = "Microsoft SQL Server Schema \n Host: #{mssql_client.peerhost} \n Port: #{mssql_client.peerport} \n Instance: #{instancename} \n Version: #{version} \n====================\n\n"

    # Grab all the DB schema and save it as notes
    mssql_schema = get_mssql_schema
    if mssql_schema.nil? or mssql_schema.empty?
      print_good output if datastore['DISPLAY_RESULTS']
      print_warning('No schema information found')
      return nil
    end
    mssql_schema.each do |db|
      report_note(
        :host  => mssql_client.peerhost,
        :type  => "mssql.db.schema",
        :data  => { :database => db },
        :port  => mssql_client.peerport,
        :proto => 'tcp',
        :update => :unique_data
      )
    end
    output << YAML.dump(mssql_schema)
    this_service = report_service(
          :host  => mssql_client.peerhost,
          :port => mssql_client.peerport,
          :name => 'mssql',
          :proto => 'tcp'
          )
    store_loot('mssql_schema', "text/plain", mssql_client.peerhost, output, "#{mssql_client.peerhost}_mssql_schema.txt", "MS SQL Schema", this_service)
    print_good output if datastore['DISPLAY_RESULTS']
  end

  def get_mssql_schema
    mssql_db_names = get_db_names()
    mssql_schema=[]
    unless mssql_db_names.nil?
      mssql_db_names.each do |dbname|
        next if dbname[0] == 'model' or dbname[0] == 'master' or dbname[0] == 'msdb' or dbname[0] == 'tempdb'
        tmp_db = {}
        tmp_tblnames = get_tbl_names(dbname[0])
        unless tmp_tblnames.nil?
          tmp_db['DBName']= dbname[0]
          tmp_db['Tables'] = []
          tmp_tblnames.each do |tblname|
            next if tblname[0].nil?
            tmp_tbl = {}
            tmp_tbl['TableName'] = tblname[0]
            tmp_tbl['Columns'] = []
            tmp_columns = get_columns(dbname[0], tblname[1])
            unless tmp_columns.nil?
              tmp_columns.each do |column|
                next if column[0].nil?
                tmp_column = {}
                tmp_column['ColumnName'] = column[0]
                tmp_column['ColumnType'] = column[1]
                tmp_column['ColumnLength'] = column[2]
                tmp_tbl['Columns'] << tmp_column
              end
            end
            tmp_db['Tables'] << tmp_tbl
          end
        end
        mssql_schema << tmp_db
      end
    end
    return mssql_schema
  end


  # Gets all of the Databases on this Instance
  def get_db_names
    results = mssql_query(mssql_db_names())[:rows]
    return results
  end

  # Gets all the table names for the given DB
  def get_tbl_names(db_name)
    results = mssql_query("SELECT name,id FROM #{db_name}..sysobjects WHERE xtype = 'U'")[:rows]
    return results
  end

  # TODO: This should be split up, I fear nil problems in these query/response parsings
  def get_columns(db_name, table_id)
    results = mssql_query("Select syscolumns.name,systypes.name,syscolumns.length from #{db_name}..syscolumns JOIN #{db_name}..systypes ON syscolumns.xtype=systypes.xtype WHERE syscolumns.id=#{table_id}")[:rows]
    return results
  end
end
