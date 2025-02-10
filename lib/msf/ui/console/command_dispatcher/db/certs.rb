# -*- coding: binary -*-

module Msf::Ui::Console::CommandDispatcher::Db::Certs
  #
  # Tab completion for the certs command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line. words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  def cmd_certs_tabs(str, words)
    tabs = []

    case words.length
    when 1
      tabs = @@certs_opts.option_keys.select { |opt| opt.start_with?(str) }
    when 2
      tabs = if words[1] == '-e' || words[1] == '--export'
               tab_complete_filenames(str, words)
             else
               []
             end
    end

    tabs
  end

  def cmd_certs_help
    print_line 'List Pkcs12 certificate bundles in the database'
    print_line 'Usage: certs [options] [username[@domain_upn_format]]'
    print_line
    print @@certs_opts.usage
    print_line
  end

  @@certs_opts = Rex::Parser::Arguments.new(
    ['-v', '--verbose'] => [false, 'Verbose output'],
    ['-d', '--delete'] => [ false, 'Delete *all* matching pkcs12 entries'],
    ['-h', '--help'] => [false, 'Help banner'],
    ['-i', '--index'] => [true, 'Pkcs12 entry ID(s) to search for, e.g. `-i 1` or `-i 1,2,3` or `-i 1 -i 2 -i 3`'],
    ['-a', '--activate'] => [false, 'Activates *all* matching pkcs12 entries'],
    ['-A', '--deactivate'] => [false, 'Deactivates *all* matching pkcs12 entries'],
    ['-e', '--export'] => [true, 'The file path where to export the matching pkcs12 entry']
  )

  def cmd_certs(*args)
    return unless active?

    entries_affected = 0
    mode = :list
    id_search = []
    username = nil
    verbose = false
    export_path = nil
    @@certs_opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h', '--help'
        cmd_certs_help
        return
      when '-v', '--verbose'
        verbose = true
      when '-d', '--delete'
        mode = :delete
      when '-i', '--id'
        id_search = (id_search + val.split(/,\s*|\s+/)).uniq # allows 1 or 1,2,3 or "1 2 3" or "1, 2, 3"
      when '-a', '--activate'
        mode = :activate
      when '-A', '--deactivate'
        mode = :deactivate
      when '-e', '--export'
        export_path = val
      else
        # Anything that wasn't an option is a username to search for
        username = val
      end
    end

    pkcs12_results = pkcs12_search(username: username, id_search: id_search)

    print_line('Pkcs12')
    print_line('======')

    if mode == :delete
      result = pkcs12_storage.delete(ids: pkcs12_results.map(&:id))
      entries_affected = result.size
    end

    if mode == :activate || mode == :deactivate
      pkcs12_results = set_pkcs12_status(mode, pkcs12_results)
      entries_affected = pkcs12_results.size
    end

    if export_path
      if pkcs12_results.empty?
        print_error('No mathing Pkcs12 entry to export')
        return
      end
      if pkcs12_results.size > 1
        print_error('More than one mathing Pkcs12 entry found. Filter with `-i` and/or provide a username')
        return
      end

      raw_data = Base64.strict_decode64(pkcs12_results.first.private_cred.data)
      ::File.binwrite(::File.expand_path(export_path), raw_data)
      return
    end

    if pkcs12_results.empty?
      print_line('No Pkcs12')
      print_line
      return
    end

    if verbose
      pkcs12_results.each.with_index do |pkcs12_result, index|
        print_line "Certificate[#{index}]:"
        print_line pkcs12_result.openssl_pkcs12.certificate.to_s
        print_line pkcs12_result.openssl_pkcs12.certificate.to_text
        print_line
      end
    else
      tbl = Rex::Text::Table.new(
        {
          'Columns' => ['id', 'username', 'realm', 'subject', 'issuer', 'ADCS CA', 'ADCS Template', 'status'],
          'SortIndex' => -1,
          'WordWrap' => false,
          'Rows' => pkcs12_results.map do |pkcs12|
            [
              pkcs12.id,
              pkcs12.username,
              pkcs12.realm,
              pkcs12.openssl_pkcs12.certificate.subject.to_s,
              pkcs12.openssl_pkcs12.certificate.issuer.to_s,
              pkcs12.adcs_ca,
              pkcs12.adcs_template,
              pkcs12_status(pkcs12)
            ]
          end
        }
      )
      print_line(tbl.to_s)
    end

    case mode
    when :delete
      print_status("Deleted #{entries_affected} #{entries_affected > 1 ? 'entries' : 'entry'}") if entries_affected > 0
    when :activate
      print_status("Activated #{entries_affected} #{entries_affected > 1 ? 'entries' : 'entry'}") if entries_affected > 0
    when :deactivate
      print_status("Deactivated #{entries_affected} #{entries_affected > 1 ? 'entries' : 'entry'}") if entries_affected > 0
    end
  end


  # @param [String, nil] username Search for pkcs12 associated with this username
  # @param [Array<Integer>, nil] id_search List of pkcs12 IDs to search for
  # @param [Workspace] workspace to search against
  # @option [Symbol] :workspace The framework.db.workspace to search against (optional)
  # @return [Array<>]
  def pkcs12_search(username: nil, id_search: nil, workspace: framework.db.workspace)
    pkcs12_results = []

    if id_search.present?
      begin
        pkcs12_results += id_search.flat_map do |id|
          pkcs12_storage.pkcs12(
            workspace: workspace,
            id: id
          )
        end
      rescue ActiveRecord::RecordNotFound => e
        wlog("Record Not Found: #{e.message}")
        print_warning("Not all records with the ids: #{id_search} could be found.")
        print_warning('Please ensure all ids specified are available.')
      end
    elsif username.present?
      realm = nil
      if username.include?('@')
        username, realm = username.split('@', 2)
      end
      pkcs12_results += pkcs12_storage.pkcs12(
        workspace: workspace,
        username: username,
        realm: realm
      )
    else
      pkcs12_results += pkcs12_storage.pkcs12(
        workspace: workspace
      )
    end

    pkcs12_results.sort_by do |pkcs12|
      [pkcs12.realm, pkcs12.username]
    end
  end


  private

  # @return [Msf::Exploit::Remote::Kerberos::Ticket::Storage::ReadWrite]
  def pkcs12_storage
    @pkcs12_storage ||= Msf::Exploit::Remote::Pkcs12::Storage.new(framework: framework)
  end

  # Gets the status of a Pkcs12
  #
  # @param [Msf::Exploit::Remote::Pkcs12::Storage]
  # @return [String] Status of the Pkcs12
  def pkcs12_status(pkcs12)
    if pkcs12.expired?
      '>>expired<<'
    elsif pkcs12.status.blank?
      'active'
    else
      pkcs12.status
    end
  end

  # Sets the status of the Pkcs12
  #
  # @param [Symbol] mode The status (:activate or :deactivate) to apply to the Pkcs12(s)
  # @param [Array<StoredPkcs12>] tickets The Pkcs12 which statuses are to be updated
  # @return [Array<StoredPkcs12>]
  def set_pkcs12_status(mode, pkcs12)
    if mode == :activate
      pkcs12_storage.activate(ids: pkcs12.map(&:id))
    elsif mode == :deactivate
      pkcs12_storage.deactivate(ids: pkcs12.map(&:id))
    end
  end
end
