module MsfdbHelpers
  class DbInterface

    def initialize(options)
      @options = options
    end

    def init
      raise NotImplementedError
    end

    def delete
      raise NotImplementedError
    end

    def start
      raise NotImplementedError
    end

    def stop
      raise NotImplementedError
    end

    def restart
      raise NotImplementedError
    end

    def status
      raise NotImplementedError
    end

    def write_db_client_auth_config(client_auth_config)
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
      []
    end

    def run_cmd(cmd, input: nil, env: {})
      puts "run_cmd: cmd=#{cmd}, input=#{input}, env=#{env}" if @options[:debug]

      output, status = Open3.capture2e(env, cmd)
      if @options[:debug]
        puts "'#{cmd}' returned #{status.exitstatus}"
        puts output
      end
      status.exitstatus
    end

    def run_psql(cmd, db_name: 'postgres')
      if @options[:debug]
        puts "psql -p #{@options[:db_port]} -c \"#{cmd};\" #{db_name}"
      end

      run_cmd("psql -p #{@options[:db_port]} -c \"#{cmd};\" #{db_name}")
    end

  end
end
