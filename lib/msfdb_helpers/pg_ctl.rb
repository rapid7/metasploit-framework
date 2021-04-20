require 'msfdb_helpers/db_interface'

class PgCtl < DbInterface

  def initialize(db_path:, options:, localconf:, db_conf:)
    @db = db_path
    @options = options
    @localconf = localconf
    @db_conf = db_conf
    super()
  end

  def init_db
    puts "Creating database at #{@db}"
    Dir.mkdir(@db)
    run_cmd("initdb --auth-host=trust --auth-local=trust -E UTF8 #{@db}")

    File.open("#{@db}/postgresql.conf", 'a') do |f|
      f.puts "port = #{@options[:db_port]}"
    end
  end

  def delete_db
    if Dir.exist?(@db)
      stop_db

      if @options[:delete_existing_data]
        puts "Deleting all data at #{@db}"
        FileUtils.rm_rf(@db)
      end

      if @options[:delete_existing_data]
        File.delete(@db_conf)
      end
    else
      puts "No data at #{@db}, doing nothing"
    end
  end

  def reinit_db
    delete_db
    init_db
  end

  def start_db
    if run_cmd("pg_ctl -o \"-p #{@options[:db_port]}\" -D #{@db} status") == 0
      puts "Database already started at #{@db}"
      return true
    end

    print "Starting database at #{@db}..."
    run_cmd("pg_ctl -o \"-p #{@options[:db_port]}\" -D #{@db} -l #{@db}/log start")
    sleep(2)
    if run_cmd("pg_ctl -o \"-p #{@options[:db_port]}\" -D #{@db} status") != 0
      puts 'failed'.red.bold.to_s
      false
    else
      puts 'success'.green.bold.to_s
      true
    end
  end

  def stop_db
    if run_cmd("pg_ctl -o \"-p #{@options[:db_port]}\" -D #{@db} status") == 0
      puts "Stopping database at #{@db}"
      run_cmd("pg_ctl -o \"-p #{@options[:db_port]}\" -D #{@db} stop")
    else
      puts "Database is no longer running at #{@db}"
    end
  end

  def restart_db
    stop_db
    start_db
  end

  def status_db
    if Dir.exist?(@db)
      if run_cmd("pg_ctl -o \"-p #{@options[:db_port]}\" -D #{@db} status") == 0
        puts "Database started at #{@db}"
      else
        puts "Database is not running at #{@db}"
      end
    else
      puts "No database found at #{@db}"
    end
  end

  def write_db_client_auth_config
    client_auth_config = "#{@db}/pg_hba.conf"
    puts "Writing client authentication configuration file #{client_auth_config}"
    File.open(client_auth_config, 'w') do |f|
      f.puts "host    \"#{@options[:msf_db_name]}\"      \"#{@options[:msf_db_user]}\"      127.0.0.1/32           md5"
      f.puts "host    \"#{@options[:msftest_db_name]}\"  \"#{@options[:msftest_db_user]}\"  127.0.0.1/32           md5"
      f.puts "host    \"postgres\"  \"#{@options[:msftest_db_user]}\"  127.0.0.1/32           md5"
      f.puts 'host    "template1"   all                127.0.0.1/32           trust'
      if Gem.win_platform?
        f.puts 'host    all             all                127.0.0.1/32           trust'
        f.puts 'host    all             all                ::1/128                trust'
      else
        f.puts 'local   all             all                                       trust'
      end
    end
  end
end
