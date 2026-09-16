##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http/c2_profile_generator'

class MetasploitModule < Msf::Auxiliary

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Malleable C2 HTTP Profile Generator',
      'Description' => %q{
        Generates a randomised Malleable C2 HTTP profile (.profile) that can
        be loaded via the MALLEABLEC2 handler option to blend Meterpreter
        HTTP/S traffic into a chosen application persona.

        Each run produces unique URI paths, header values, and token prefixes
        so that no two engagements share the same network signature. The
        generated file is written to disk and the path is printed for use
        with the reverse_http/reverse_https handler.

        Personas
        --------
        cdn       - Static CDN asset requests + RUM beacon POSTs.
                    Session UUID hidden in __cf_bm cookie (Cloudflare Bot
                    Management format).  NDR rules that whitelist Cloudflare
                    origin traffic pass this without inspection.

        office365 - Microsoft Graph API mailbox polling (GET) and message
                    send (POST). Bearer token in Authorization header is
                    indistinguishable from a real Azure AD access token.

        github    - GitHub REST API commit listing (GET) and issue comment
                    creation (POST). Matches git CLI and IDE plugin traffic.

        slack     - Slack Web API channel history polling and chat posting.
                    Token format matches real Slack bot tokens (xoxb-*).

        Recommended handler settings when loading the generated profile:

          set HttpServerName   <see comment in generated file>
          set HttpUnknownRequestResponse <persona-appropriate body>
          set MALLEABLEC2 /path/to/generated.profile

        The profile sleeptime/jitter values are also written so the beacon
        interval is varied by the configured percentage each cycle, disrupting
        fixed-interval beaconing detection.
      },
      'Author'      => 'msf',
      'License'     => MSF_LICENSE,
      'Notes'       => {
        'Stability'   => [CRASH_SAFE],
        'Reliability' => [],
        'SideEffects' => [ARTIFACTS_ON_DISK]
      }
    ))

    register_options([
      OptEnum.new('PERSONA', [
        true,
        'Application persona to mimic',
        'cdn',
        Rex::Proto::Http::C2ProfileGenerator::PERSONAS.map(&:to_s)
      ]),
      OptString.new('OUTFILE', [
        true,
        'Path to write the generated profile',
        '/tmp/engagement.profile'
      ]),
      OptInt.new('SLEEPTIME', [
        true,
        'Beacon interval in milliseconds',
        5000
      ]),
      OptInt.new('JITTER', [
        true,
        'Beacon jitter percentage (0-99)',
        20
      ])
    ])
  end

  def run
    persona    = datastore['PERSONA'].to_sym
    outfile    = datastore['OUTFILE']
    sleeptime  = datastore['SLEEPTIME'].to_i
    jitter     = datastore['JITTER'].to_i.clamp(0, 99)

    print_status("Generating #{persona.upcase} persona profile (sleeptime=#{sleeptime}ms, jitter=#{jitter}%)")

    profile = Rex::Proto::Http::C2ProfileGenerator.generate(
      persona:   persona,
      sleeptime: sleeptime,
      jitter:    jitter
    )

    begin
      File.write(outfile, profile)
    rescue => e
      fail_with(Failure::Unknown, "Failed to write profile: #{e}")
    end

    print_good("Profile written to: #{outfile}")
    print_line('')
    print_line('--- Preview (first 30 lines) ---')
    profile.each_line.first(30).each { |l| print_line(l.chomp) }
    print_line('...')
    print_line('')
    print_status('Load in your handler with:')
    print_status("  set MALLEABLEC2 #{outfile}")

    store_loot(
      'c2_profile',
      'text/plain',
      '127.0.0.1',
      profile,
      'c2_profile.profile',
      "#{persona} C2 profile"
    )
  end
end
