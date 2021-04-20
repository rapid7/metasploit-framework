require 'msfdb_helpers/db_interface'

class PgCtlcluster < DbInterface

  def initialize(db_path:, options:, localconf:, db_conf:)
    @db = db_path
    @options = options
    @pg_version = get_postgres_version
    @localconf = localconf
    @db_conf = db_conf
    @pg_cluster_conf_root = "#{@localconf}/.local/etc/postgresql"
    ENV['PG_CLUSTER_CONF_ROOT'] = @pg_cluster_conf_root
    super()
  end

  def init
    puts "Creating database at #{@db}"
    Dir.mkdir(@db)
    FileUtils.mkdir_p(@pg_cluster_conf_root)
    run_cmd("pg_createcluster --user=$(whoami) -l #{@db}/log -d #{@db} -s /tmp --encoding=UTF8 #{@pg_version} #{@options[:msf_db_name]} -- --username=$(whoami) --auth-host=trust --auth-local=trust")
    File.open("#{@pg_cluster_conf_root}/#{@pg_version}/#{@options[:msf_db_name]}/postgresql.conf", 'a') do |f|
      f.puts "port = #{@options[:db_port]}"
    end
  end

  def delete
    if Dir.exist?(@db)
      stop

      if @options[:delete_existing_data]
        puts "Deleting all data at #{@db}"
        run_cmd("pg_dropcluster #{@pg_version} #{@options[:msf_db_name]}")
        FileUtils.rm_rf(@db)
        FileUtils.rm_rf("#{@localconf}/.local/etc/postgresql")
        File.delete(@db_conf)
      end
    else
      puts "No data at #{@db}, doing nothing"
    end
  end

  def reinit
    delete
    init
  end

  def start
    print "Starting database at #{@db}..."
    status = run_cmd("pg_ctlcluster #{@pg_version} #{@options[:msf_db_name]} start -- -o \"-p #{@options[:db_port]}\" -D #{@db} -l #{@db}/log")
    case status
    when 0
      puts 'success'.green.bold.to_s
      return true
    when 2
      puts "Database already started at #{@db}"
      return true
    else
      puts 'failed'.red.bold.to_s
      return false
    end
  end

  def stop
    run_cmd("pg_ctlcluster #{get_postgres_version} #{@options[:msf_db_name]} stop -- -o \"-p #{@options[:db_port]}\" -D #{@db}")
  end

  def restart
    run_cmd("pg_ctlcluster #{@pg_version} #{@options[:msf_db_name]} reload -- -o \"-p #{@options[:db_port]}\" -D #{@db} -l #{@db}/log")
  end

  def status
    if Dir.exist?(@db)
      if run_cmd("pg_ctlcluster #{@pg_version} #{@options[:msf_db_name]} status -- -o \"-p #{@options[:db_port]}\" -D #{@db}") == 0
        puts "Database started at #{@db}"
      else
        puts "Database is not running at #{@db}"
      end
    else
      puts "No database found at #{@db}"
    end
  end

  def write_db_client_auth_config
    client_auth_config = "#{@pg_cluster_conf_root}/#{@pg_version}/#{@options[:msf_db_name]}/pg_hba.conf"
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

  def self.requirements
    %w(psql pg_ctlcluster pg_dropcluster pg_createcluster pg_config)
  end

  private

  def get_postgres_version
    _stdin, stdout, _stderr, _wait_thr = Open3.popen3('pg_config --version')
    # Example outputs
    # PostgreSQL 12.6 (Ubuntu 12.6-0ubuntu0.20.04.1)
    # PostgreSQL 13.2 (Debian 13.2-1)
    # PostgreSQL 11.11
    /PostgreSQL\s(?<version>\d+)\.\d+/ =~ stdout.gets
    version
  end

  def run_cmd(cmd, input: nil, env: {})
    exitstatus = 0
    err = out = ''

    puts "run_cmd: cmd=#{cmd}, input=#{input}, env=#{env}" if @options[:debug]

    Open3.popen3(env, cmd) do |stdin, stdout, stderr, wait_thr|
      stdin.puts(input) if input
      if @options[:debug]
        err = stderr.read
        out = stdout.read
      end
      exitstatus = wait_thr.value.exitstatus
    end

    if @options[:debug]
      puts "'#{cmd}' returned #{exitstatus}"
      puts out
      puts err
    end

    exitstatus
  end

end
