# -*- coding: binary -*-

module Msf::Ui::Console::CommandDispatcher::Db::Klist
  #
  # Tab completion for the klist command
  #
  # @param str [String] the string currently being typed before tab was hit
  # @param words [Array<String>] the previously completed words on the command line.  words is always
  # at least 1 when tab completion has reached this stage since the command itself has been completed
  def cmd_klist_tabs(str, words)
    if words.length == 1
      @@klist_opts.option_keys.select { |opt| opt.start_with?(str) }
    end
  end

  def cmd_klist_help
    print_line 'List Kerberos tickets in the database'
    print_line 'Usage: klist [options] [hosts]'
    print_line
    print @@klist_opts.usage
    print_line
  end

  @@klist_opts = Rex::Parser::Arguments.new(
    ['-v', '--verbose'] => [false, 'Verbose output'],
    ['-d', '--delete'] => [ false, 'Delete *all* matching kerberos entries'],
    ['-h', '--help'] => [false, 'Help banner'],
    ['-i', '--index'] => [true, 'Kerberos entry ID(s) to search for, e.g. `-i 1` or `-i 1,2,3` or `-i 1 -i 2 -i 3`'],
    ['-a', '--activate'] => [false, 'Activates *all* matching kerberos entries'],
    ['-A', '--deactivate'] => [false, 'Deactivates *all* matching kerberos entries']
  )

  def cmd_klist(*args)
    return unless active?

    entries_affected = 0
    mode = :list
    host_ranges = []
    id_search = []
    verbose = false
    @@klist_opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h', '--help'
        cmd_klist_help
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
      else
        # Anything that wasn't an option is a host to search for
        unless arg_host_range(val, host_ranges)
          return
        end
      end
    end

    # Sentinel value meaning all
    host_ranges.push(nil) if host_ranges.empty?
    id_search = nil if id_search.empty?

    ticket_results = ticket_search(host_ranges, id_search)

    print_line('Kerberos Cache')
    print_line('==============')

    if ticket_results.empty?
      print_line('No tickets')
      print_line
      return
    end

    if mode == :delete
      result = kerberos_ticket_storage.delete_tickets(ids: ticket_results.map(&:id))
      entries_affected = result.size
    end

    if mode == :activate || mode == :deactivate
      result = set_activation_status(mode, ticket_results)
      entries_affected = result.size
      # Update the contents of ticket results to display the updated status values
      # TODO: should be able to use the results returned from updating loot
      # but it returns a base 64'd data field which breaks when bindata tries to parse it as a ccache
      ticket_results = ticket_search(host_ranges, id_search)
    end

    if verbose
      ticket_results.each.with_index do |ticket_result, index|
        ticket_details = Rex::Proto::Kerberos::CredentialCache::Krb5CcachePresenter.new(ticket_result.ccache).present
        print_line "Cache[#{index}]:"
        print_line ticket_details.indent(2)
        print_line
      end
    else
      tbl = Rex::Text::Table.new(
        {
          'Columns' => ['id', 'host', 'principal', 'sname', 'issued', 'status', 'path'],
          'SortIndex' => -1,
          # For now, don't perform any word wrapping on the table as it breaks the workflow of
          # copying file paths and pasting them into applications
          'WordWrap' => false,
          'Rows' => ticket_results.map do |ticket|
            [
              ticket.id,
              ticket.host_address,
              ticket.principal,
              ticket.sname,
              ticket.starttime,
              ticket_status(ticket),
              ticket.path
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

  protected

  # @return [Msf::Exploit::Remote::Kerberos::Ticket::Storage::ReadWrite]
  def kerberos_ticket_storage
    @kerberos_ticket_storage ||= Msf::Exploit::Remote::Kerberos::Ticket::Storage::ReadWrite.new(framework: framework)
  end

  private

  # Gets the status of a ticket
  #
  # @param [Msf::Exploit::Remote::Kerberos::Ticket::Storage::StoredTicket]
  # @return [String] Status of the ticket
  def ticket_status(ticket)
    if ticket.expired?
      '>>expired<<'
    elsif ticket.status.blank?
      'active'
    else
      ticket.status
    end
  end

  # Sets the status of the tickets
  #
  # @param [Symbol] mode The status (:activate or :deactivate) to apply to the ticket(s)
  # @param [Array<StoredTicket>] tickets The tickets which statuses are to be updated
  # @return [Array<StoredTicket>]
  def set_activation_status(mode, tickets)
    if mode == :activate
      kerberos_ticket_storage.activate_ccache(ids: tickets.map(&:id))
    elsif mode == :deactivate
      kerberos_ticket_storage.deactivate_ccache(ids: tickets.map(&:id))
    end
  end

  # @param [Array<Rex::Socket::RangeWalker>] host_ranges Search for tickets associated with these hosts
  # @param [Array<Integer>, nil] id_search List of ticket IDs to search for
  # @return [Array<Msf::Exploit::Remote::Kerberos::Ticket::Storage::StoredTicket>]
  def ticket_search(host_ranges, id_search)
    ticket_results = []

    # Iterating over each id here since the remote db doesn't support bulk id searches
    if id_search
      begin
        ticket_results += id_search.flat_map do |id|
          kerberos_ticket_storage.tickets(
            workspace: framework.db.workspace,
            id: id
          )
        end
      rescue ActiveRecord::RecordNotFound => e
        wlog("Record Not Found: #{e.message}")
        print_warning("Not all records with the ids: #{id_search} could be found.")
        print_warning('Please ensure all ids specified are available.')
      end
    else
      each_host_range_chunk(host_ranges) do |host_search|
        next if host_search&.empty?

        ticket_results += kerberos_ticket_storage.tickets(
          workspace: framework.db.workspace,
          host: host_search
        )
      end
      host_ranges.each { |range| range.reset unless range.nil? } # Reset the Rex::Socket::RangeWalker so it can be re-used
    end

    ticket_results.sort_by do |ticket|
      ticket_host_address = ticket.host_address.blank? ? '0.0.0.0' : ticket.host_address
      [::IPAddr.new(ticket_host_address).to_i, ticket.starttime.to_i]
    end
  end
end
