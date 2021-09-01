# -*- coding: binary -*-

require 'rexml/document'
require 'metasploit/framework/password_crackers/hashcat/formatter'
require 'metasploit/framework/password_crackers/jtr/formatter'

module Msf
module Ui
module Console
module CommandDispatcher

class Creds
  require 'tempfile'

  include Msf::Ui::Console::CommandDispatcher
  include Metasploit::Credential::Creation
  include Msf::Ui::Console::CommandDispatcher::Common

  #
  # The dispatcher's name.
  #
  def name
    "Credentials Backend"
  end

  #
  # Returns the hash of commands supported by this dispatcher.
  #
  def commands
    {
      "creds" => "List all credentials in the database"
    }
  end

  def allowed_cred_types
    %w(password ntlm hash) + Metasploit::Credential::NonreplayableHash::VALID_JTR_FORMATS
  end

  #
  # Returns true if the db is connected, prints an error and returns
  # false if not.
  #
  # All commands that require an active database should call this before
  # doing anything.
  # TODO: abstract the db methods to a mixin that can be used by both dispatchers
  #
  def active?
    if not framework.db.active
      print_error("Database not connected")
      return false
    end
    true
  end

  #
  # Miscellaneous option helpers
  #

  #
  # Can return return active or all, on a certain host or range, on a
  # certain port or range, and/or on a service name.
  #
  def cmd_creds(*args)
    return unless active?

    # Short-circuit help
    if args.delete("-h") || args.delete("--help")
      cmd_creds_help
      return
    end

    subcommand = args.shift

    case subcommand
    when 'help'
      cmd_creds_help
    when 'add'
      creds_add(*args)
    else
      # then it's not actually a subcommand
      args.unshift(subcommand) if subcommand
      creds_search(*args)
    end

  end

  #
  # TODO: this needs to be cleaned up to use the new syntax
  #
  def cmd_creds_help
    print_line
    print_line "With no sub-command, list credentials. If an address range is"
    print_line "given, show only credentials with logins on hosts within that"
    print_line "range."

    print_line
    print_line "Usage - Listing credentials:"
    print_line "  creds [filter options] [address range]"
    print_line
    print_line "Usage - Adding credentials:"
    print_line "  creds add uses the following named parameters."
    {
      user:         'Public, usually a username',
      password:     'Private, private_type Password.',
      ntlm:         'Private, private_type NTLM Hash.',
      postgres:     'Private, private_type postgres MD5',
      'ssh-key' =>  'Private, private_type SSH key, must be a file path.',
      hash:         'Private, private_type Nonreplayable hash',
      jtr:          'Private, private_type John the Ripper hash type.',
      realm:        'Realm, ',
      'realm-type'=>"Realm, realm_type (#{Metasploit::Model::Realm::Key::SHORT_NAMES.keys.join(' ')}), defaults to domain."
    }.each_pair do |keyword, description|
      print_line "    #{keyword.to_s.ljust 10}:  #{description}"
    end
    print_line
    print_line "Examples: Adding"
    print_line "   # Add a user, password and realm"
    print_line "   creds add user:admin password:notpassword realm:workgroup"
    print_line "   # Add a user and password"
    print_line "   creds add user:guest password:'guest password'"
    print_line "   # Add a password"
    print_line "   creds add password:'password without username'"
    print_line "   # Add a user with an NTLMHash"
    print_line "   creds add user:admin ntlm:E2FC15074BF7751DD408E6B105741864:A1074A69B1BDE45403AB680504BBDD1A"
    print_line "   # Add a NTLMHash"
    print_line "   creds add ntlm:E2FC15074BF7751DD408E6B105741864:A1074A69B1BDE45403AB680504BBDD1A"
    print_line "   # Add a Postgres MD5"
    print_line "   creds add user:postgres postgres:md5be86a79bf2043622d58d5453c47d4860"
    print_line "   # Add a user with an SSH key"
    print_line "   creds add user:sshadmin ssh-key:/path/to/id_rsa"
    print_line "   # Add a user and a NonReplayableHash"
    print_line "   creds add user:other hash:d19c32489b870735b5f587d76b934283 jtr:md5"
    print_line "   # Add a NonReplayableHash"
    print_line "   creds add hash:d19c32489b870735b5f587d76b934283"

    print_line
    print_line "General options"
    print_line "  -h,--help             Show this help information"
    print_line "  -o <file>             Send output to a file in csv/jtr (john the ripper) format."
    print_line "                        If file name ends in '.jtr', that format will be used."
    print_line "                        If file name ends in '.hcat', the hashcat format will be used."
    print_line "                        csv by default."
    print_line "  -d,--delete           Delete one or more credentials"
    print_line
    print_line "Filter options for listing"
    print_line "  -P,--password <text>  List passwords that match this text"
    print_line "  -p,--port <portspec>  List creds with logins on services matching this port spec"
    print_line "  -s <svc names>        List creds matching comma-separated service names"
    print_line "  -u,--user <text>      List users that match this text"
    print_line "  -t,--type <type>      List creds of the specified type: password, ntlm, hash or any valid JtR format"
    print_line "  -O,--origins <IP>     List creds that match these origins"
    print_line "  -r,--realm <realm>    List creds that match this realm"
    print_line "  -R,--rhosts           Set RHOSTS from the results of the search"
    print_line "  -v,--verbose          Don't truncate long password hashes"

    print_line
    print_line "Examples, John the Ripper hash types:"
    print_line "  Operating Systems (starts with)"
    print_line "    Blowfish ($2a$)   : bf"
    print_line "    BSDi     (_)      : bsdi"
    print_line "    DES               : des,crypt"
    print_line "    MD5      ($1$)    : md5"
    print_line "    SHA256   ($5$)    : sha256,crypt"
    print_line "    SHA512   ($6$)    : sha512,crypt"
    print_line "  Databases"
    print_line "    MSSQL             : mssql"
    print_line "    MSSQL 2005        : mssql05"
    print_line "    MSSQL 2012/2014   : mssql12"
    print_line "    MySQL < 4.1       : mysql"
    print_line "    MySQL >= 4.1      : mysql-sha1"
    print_line "    Oracle            : des,oracle"
    print_line "    Oracle 11         : raw-sha1,oracle11"
    print_line "    Oracle 11 (H type): dynamic_1506"
    print_line "    Oracle 12c        : oracle12c"
    print_line "    Postgres          : postgres,raw-md5"

    print_line
    print_line "Examples, listing:"
    print_line "  creds               # Default, returns all credentials"
    print_line "  creds 1.2.3.4/24    # Return credentials with logins in this range"
    print_line "  creds -O 1.2.3.4/24 # Return credentials with origins in this range"
    print_line "  creds -p 22-25,445  # nmap port specification"
    print_line "  creds -s ssh,smb    # All creds associated with a login on SSH or SMB services"
    print_line "  creds -t ntlm       # All NTLM creds"
    print_line

    print_line "Example, deleting:"
    print_line "  # Delete all SMB credentials"
    print_line "  creds -d -s smb"
    print_line
  end

  # @param private_type [Symbol] See `Metasploit::Credential::Creation#create_credential`
  # @param username [String]
  # @param password [String]
  # @param realm [String]
  # @param realm_type [String] A key in `Metasploit::Model::Realm::Key::SHORT_NAMES`
  def creds_add(*args)
    params = args.inject({}) do |hsh, n|
      opt = n.split(':') # Splitting the string on colons.
      hsh[opt[0]] = opt[1..-1].join(':') # everything before the first : is the key, reasembling everything after the colon. why ntlm hashes
      hsh
    end

    begin
      params.assert_valid_keys('user','password','realm','realm-type','ntlm','ssh-key','hash','address','port','protocol', 'service-name', 'jtr', 'postgres')
    rescue ArgumentError => e
      print_error(e.message)
    end

    # Verify we only have one type of private
    if params.slice('password','ntlm','ssh-key','hash', 'postgres').length > 1
      private_keys = params.slice('password','ntlm','ssh-key','hash', 'postgres').keys
      print_error("You can only specify a single Private type. Private types given: #{private_keys.join(', ')}")
      return
    end

    login_keys = params.slice('address','port','protocol','service-name')
    if login_keys.any? and login_keys.length < 3
      missing_login_keys = ['host','port','proto','service-name'] - login_keys.keys
      print_error("Creating a login requires a address, a port, and a protocol. Missing params: #{missing_login_keys}")
      return
    end

    data = {
      workspace_id: framework.db.workspace.id,
      origin_type: :import,
      filename: 'msfconsole'
    }

    data[:username] = params['user'] if params.key? 'user'

    if params.key? 'realm'
      if params.key? 'realm-type'
        if Metasploit::Model::Realm::Key::SHORT_NAMES.key? params['realm-type']
          data[:realm_key] = Metasploit::Model::Realm::Key::SHORT_NAMES[params['realm-type']]
        else
          valid = Metasploit::Model::Realm::Key::SHORT_NAMES.keys.map{|n|"'#{n}'"}.join(", ")
          print_error("Invalid realm type: #{params['realm_type']}. Valid Values: #{valid}")
        end
      else
        data[:realm_key] = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
      end
      data[:realm_value] = params['realm']
    end

    if params.key? 'password'
      data[:private_type] = :password
      data[:private_data] = params['password']
    end

    if params.key? 'ntlm'
      data[:private_type] = :ntlm_hash
      data[:private_data] = params['ntlm']
    end

    if params.key? 'ssh-key'
      begin
        key_data = File.read(params['ssh-key'])
      rescue ::Errno::EACCES, ::Errno::ENOENT => e
        print_error("Failed to add ssh key: #{e}")
      end
      data[:private_type] = :ssh_key
      data[:private_data] = key_data
    end

    if params.key? 'hash'
      data[:private_type] = :nonreplayable_hash
      data[:private_data] = params['hash']
      data[:jtr_format] = params['jtr'] if params.key? 'jtr'
    end

    if params.key? 'postgres'
      data[:private_type] = :postgres_md5
      if params['postgres'].downcase.start_with?('md5')
        data[:private_data] = params['postgres']
        data[:jtr_format] = 'postgres'
      else
        print_error("Postgres MD5 hashes should start wtih 'md5'")
      end
    end

    begin
      if login_keys.any?
        data[:address] = params['address']
        data[:port] = params['port']
        data[:protocol] = params['protocol']
        data[:service_name] = params['service-name']
        framework.db.create_credential_and_login(data)
      else
        framework.db.create_credential(data)
      end
    rescue ActiveRecord::RecordInvalid => e
      print_error("Failed to add #{data['private_type']}: #{e}")
    end
  end

  def service_from_origin(core)
    # Depending on the origin of the cred, there may or may not be a way to retrieve the associated service
    case core.origin
    when Metasploit::Credential::Origin::Service
      return core.origin.service
    end
  end

  def build_service_info(service)
    if service.name.present?
      info = "#{service.port}/#{service.proto} (#{service.name})"
    else
      info = "#{service.port}/#{service.proto}"
    end
    info
  end

  def creds_search(*args)
    host_ranges   = []
    origin_ranges = []
    port_ranges   = []
    svcs          = []
    rhosts        = []
    opts          = {}

    set_rhosts = false
    truncate = true

    cred_table_columns = [ 'host', 'origin' , 'service', 'public', 'private', 'realm', 'private_type', 'JtR Format' ]
    delete_count = 0
    search_term = nil

    while (arg = args.shift)
      case arg
      when '-o'
        output_file = args.shift
        if (!output_file)
          print_error('Invalid output filename')
          return
        end
        output_file = ::File.expand_path(output_file)
        truncate = false
      when '-p', '--port'
        unless (arg_port_range(args.shift, port_ranges, true))
          return
        end
      when '-t', '--type'
        ptype = args.shift
        opts[:ptype] = ptype
        if (!ptype)
          print_error('Argument required for -t')
          return
        end
      when '-s', '--service'
        service = args.shift
        if (!service)
          print_error('Argument required for -s')
          return
        end
        svcs = service.split(/[\s]*,[\s]*/)
        opts[:svcs] = svcs
      when '-P', '--password'
        if !(opts[:pass] = args.shift)
          print_error('Argument required for -P')
          return
        end
      when '-u', '--user'
        if !(opts[:user] = args.shift)
          print_error('Argument required for -u')
          return
        end
      when '-d', '--delete'
        mode = :delete
      when '-R', '--rhosts'
        set_rhosts = true
      when '-O', '--origins'
        hosts = args.shift
        opts[:hosts] = hosts
        if !hosts
          print_error('Argument required for -O')
          return
        end
        arg_host_range(hosts, origin_ranges)
      when '-S', '--search-term'
        search_term = args.shift
        opts[:search_term] = search_term
      when '-v', '--verbose'
        truncate = false
      when '-r', '--realm'
        opts[:realm] = args.shift
      else
        # Anything that wasn't an option is a host to search for
        unless (arg_host_range(arg, host_ranges))
          return
        end
      end
    end

    # If we get here, we're searching.  Delete implies search

    if ptype
      type = case ptype
             when 'password'
               Metasploit::Credential::Password
             when 'hash'
               Metasploit::Credential::PasswordHash
             when 'ntlm'
               Metasploit::Credential::NTLMHash
             when *Metasploit::Credential::NonreplayableHash::VALID_JTR_FORMATS
               opts[:jtr_format] = ptype
               Metasploit::Credential::NonreplayableHash
             else
               print_error("Unrecognized credential type #{ptype} -- must be one of #{allowed_cred_types.join(',')}")
               return
             end
    end

    opts[:type] = type if type

    # normalize
    ports = port_ranges.flatten.uniq
    opts[:ports] = ports unless ports.empty?
    svcs.flatten!
    tbl_opts = {
      'Header'  => "Credentials",
      # For now, don't perform any word wrapping on the cred table as it breaks the workflow of
      # copying credentials and pasting them into applications
      'WordWrap' => false,
      'Columns' => cred_table_columns,
      'SearchTerm' => search_term
    }

    opts[:workspace] = framework.db.workspace
    query = framework.db.creds(opts)
    matched_cred_ids = []

    if output_file&.ends_with?('.hcat')
      output_file = ::File.open(output_file, 'wb')
      output_formatter = method(:hash_to_hashcat)
    elsif output_file&.ends_with?('.jtr')
      output_file = ::File.open(output_file, 'wb')
      output_formatter = method(:hash_to_jtr)
    else
      output_file = ::File.open(output_file, 'wb') unless output_file.blank?
      tbl = Rex::Text::Table.new(tbl_opts)
    end

    filtered_query(query, opts, origin_ranges, host_ranges) do |core, service, origin|
      matched_cred_ids << core.id

      if output_file && output_formatter
        formatted = output_formatter.call(core)
        output_file.puts(formatted) unless formatted.blank?
      end

      unless tbl.nil?
        public_val = core.public ? core.public.username : ''
        private_val = core.private ? core.private.to_s : ''
        if truncate && private_val.to_s.length > 87
          private_val = "#{private_val[0,87]} (TRUNCATED)"
        end
        realm_val = core.realm ? core.realm.value : ''
        human_val = core.private ? core.private.class.model_name.human : ''
        if human_val == ''
          jtr_val = '' #11433, private can be nil
        else
          jtr_val = core.private.jtr_format ? core.private.jtr_format : ''
        end

        if service.nil?
          host = ''
          service_info = ''
        else
          host = service.host.address
          rhosts << host unless host.blank?
          service_info = build_service_info(service)
        end

        tbl << [
          host,
          origin,
          service_info,
          public_val,
          private_val,
          realm_val,
          human_val, #private type
          jtr_val
        ]
      end
    end

    if output_file.nil?
      print_line(tbl.to_s)
    else
      output_file.write(tbl.to_csv) if output_formatter.nil?
      output_file.close
      print_status("Wrote creds to #{output_file.path}")
    end

    if mode == :delete
      result = framework.db.delete_credentials(ids: matched_cred_ids)
      delete_count = result.size
    end

    # Finally, handle the case where the user wants the resulting list
    # of hosts to go into RHOSTS.
    set_rhosts_from_addrs(rhosts.uniq) if set_rhosts
    print_status("Deleted #{delete_count} creds") if delete_count > 0
  end

  def cmd_creds_tabs(str, words)
    case words.length
    when 1
      # subcommands
      tabs = [ 'add-ntlm', 'add-password', 'add-hash', 'add-ssh-key', ]
    when 2
      tabs = if words[1] == 'add-ssh-key'
               tab_complete_filenames(str, words)
             else
               []
             end
    #when 5
    #  tabs = Metasploit::Model::Realm::Key::SHORT_NAMES.keys
    else
      tabs = []
    end
    return tabs
  end

  protected

  def filtered_query(query, opts, origin_ranges, host_ranges)
    query.each do |core|
      # Exclude non-blank username creds if that's what we're after
      if opts[:user] == '' && core.public && !(core.public.username.blank?)
        next
      end

      # Exclude non-blank password creds if that's what we're after
      if opts[:pass] == '' && core.private && !(core.private.data.blank?)
        next
      end

      origin = ''
      if core.origin.kind_of?(Metasploit::Credential::Origin::Service)
        service = framework.db.services(id: core.origin.service_id).first
        origin = service.host.address
      elsif core.origin.kind_of?(Metasploit::Credential::Origin::Session)
        session = framework.db.sessions(id: core.origin.session_id).first
        origin = session.host.address
      end

      if origin_ranges.present? && !origin_ranges.any? { |range| range.include?(origin) }
        next
      end

      if core.logins.empty?
        service = service_from_origin(core)
        next if service.nil? && host_ranges.present? # If we're filtering by login IP and we're here there's no associated login, so skip

        yield core, service, origin
      else
        core.logins.each do |login|
          service = framework.db.services(id: login.service_id).first
          # If none of this Core's associated Logins is for a host within
          # the user-supplied RangeWalker, then we don't have any reason to
          # print it out. However, we treat the absence of ranges as meaning
          # all hosts.
          if host_ranges.present? && !host_ranges.any? { |range| range.include?(service.host.address) }
            next
          end

          yield core, service, origin
        end
      end
    end
  end

end

end end end end
