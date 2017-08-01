##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'yaml'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MYSQL
  include Msf::Auxiliary::Report

  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'MYSQL Schema Dump',
      'Description'    => %Q{
          This module extracts the schema information from a
          MySQL DB server.
      },
      'Author'         => ['theLightCosine'],
      'License'        => MSF_LICENSE
    )

    register_options([
      OptBool.new('DISPLAY_RESULTS', [true, "Display the Results to the Screen", true])
      ])

  end

  def run_host(ip)

    if (not mysql_login_datastore)
      return
    end
    mysql_schema = get_schema
    mysql_schema.each do |db|
      report_note(
        :host  => rhost,
        :type  => "mysql.db.schema",
        :data  => db,
        :port  => rport,
        :proto => 'tcp',
        :update => :unique_data
      )
    end
    output = "MySQL Server Schema \n Host: #{datastore['RHOST']} \n Port: #{datastore['RPORT']} \n ====================\n\n"
    output << YAML.dump(mysql_schema)
    this_service = report_service(
          :host  => datastore['RHOST'],
          :port => datastore['RPORT'],
          :name => 'mysql',
          :proto => 'tcp'
          )
    p = store_loot('mysql_schema', "text/plain", datastore['RHOST'], output, "#{datastore['RHOST']}_mysql_schema.txt", "MySQL Schema", this_service)
    print_good("Schema stored in: #{p}")
    print_good output if datastore['DISPLAY_RESULTS']
  end


  def get_schema
    mysql_schema=[]
    res = mysql_query("show databases")
    if res.size > 0
      res.each do |row|
        next if row[0].nil?
        next if row[0].empty?
        next if row[0]== "information_schema"
        next if row[0]== "mysql"
        next if row[0]== "performance_schema"
        next if row[0]== "test"
        tmp_db ={}
        tmp_db['DBName'] = row[0]
        tmp_db['Tables'] = []
        tmp_tblnames = get_tbl_names(row[0])
        unless tmp_tblnames.nil? or tmp_tblnames.empty?
          tmp_tblnames.each do |table_name|
            tmp_tbl={}
            tmp_tbl['TableName'] = table_name
            tmp_tbl['Columns'] = []
            tmp_clmnames = get_columns(tmp_db['DBName'],table_name)
            unless tmp_clmnames.nil? or tmp_clmnames.empty?
              tmp_clmnames.each do |column|
                tmp_column = {}
                tmp_column['ColumnName'] = column[0]
                tmp_column['ColumnType'] = column[1]
                tmp_tbl['Columns'] << tmp_column
              end
            end
            tmp_db['Tables'] << tmp_tbl
          end
        end
        mysql_schema << tmp_db
      end
    end
    return mysql_schema
  end

  # Gets all of the Tables names inside the given Database
  def get_tbl_names(dbname)

    tables=[]
    res = mysql_query("SHOW tables from #{dbname}")
    if res.size > 0
      res.each do |row|
        next if row[0].nil?
        next if row[0].empty?
        tables<<row[0]
      end
    end
    return tables

  end

  def get_columns(db_name,tbl_name)
    tables=[]
    res = mysql_query("desc #{db_name}.#{tbl_name}")
    if res.size > 0
      res.each do |row|
        next if row[0].nil?
        next if row[0].empty?
        tables<< [row[0],row[1]]
      end
    end
    return tables
  end
end
