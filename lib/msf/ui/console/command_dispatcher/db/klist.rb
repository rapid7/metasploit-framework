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
    print_line 'Usage: klist [options]'
    print_line
    print @@klist_opts.usage
    print_line
  end

  @@klist_opts = Rex::Parser::Arguments.new(
    ['-v', '--verbose'] => [false, 'Verbose output'],
    ['-d', '--delete'] => [ false, 'Delete *all* matching kerberos entries' ],
    ['-h', '--help'] => [false, 'Help banner']
  )

  def cmd_klist(*args)
    return unless active?

    delete_count = 0
    mode = :list
    host_ranges = []
    verbose = false
    @@klist_opts.parse(args) do |opt, _idx, val|
      case opt
      when '-h', '--help'
        cmd_klist_help
        return
      when '-v', '--vebose'
        verbose = true
      when '-d', '--delete'
        mode = :delete
      else
        # Anything that wasn't an option is a host to search for
        unless arg_host_range(val, host_ranges)
          return
        end
      end
    end

    # Sentinel value meaning all
    host_ranges.push(nil) if host_ranges.empty?

    ticket_results = []
    each_host_range_chunk(host_ranges) do |host_search|
      next if host_search && host_search.empty?

      ticket_results += kerberos_ticket_storage.tickets(
        workspace: framework.db.workspace,
        host: host_search
      )
    end
    ticket_results.sort_by(&:host_address)

    print_line('Kerberos Cache')
    print_line('==============')

    if ticket_results.empty?
      print_line('No tickets')
      print_line
      return
    end

    if mode == :delete
      result = kerberos_ticket_storage.delete_tickets(ids: ticket_results.map(&:id))
      delete_count = result.size
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
          'Columns' => ['host', 'principal', 'sname', 'issued', 'status', 'path'],
          'SortIndex' => -1,
          # For now, don't perform any word wrapping on the table as it breaks the workflow of
          # copying file paths and pasting them into applications
          'WordWrap' => false,
          'Rows' => ticket_results.map do |ticket|
            [
              ticket.host_address,
              ticket.principal,
              ticket.sname,
              ticket.starttime,
              ticket.expired? ? '>>expired<<' : 'valid',
              ticket.path
            ]
          end
        }
      )
      print_line(tbl.to_s)
    end

    print_status("Deleted #{delete_count} #{delete_count > 1 ? 'entries' : 'entry'}") if delete_count > 0
  end

  protected

  # @return [Msf::Exploit::Remote::Kerberos::Ticket::Storage::ReadWrite]
  def kerberos_ticket_storage
    @kerberos_ticket_storage ||= Msf::Exploit::Remote::Kerberos::Ticket::Storage::ReadWrite.new(framework: framework)
  end
end
