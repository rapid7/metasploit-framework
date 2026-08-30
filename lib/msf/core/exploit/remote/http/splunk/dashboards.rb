# -*- coding: binary -*-

# This module provides a way of interacting with Splunk dashboards
module Msf::Exploit::Remote::HTTP::Splunk::Dashboards
  # Creates a new Splunk dashboard in the specified namespace
  #
  # @param namespace [String] The Splunk namespace (usually a user or app) where the dashboard will be created
  # @param name [String] The name of the dashboard
  # @param template [String] The dashboard template content
  # @param cookie [String] Valid admin's cookie
  # @return [Rex::Proto::Http::Response] HTTP response object
  def create_dashboard(namespace, name, template, cookie)
    csrf = extract_csrf_token(cookie)

    res = send_request_cgi(
      'uri' => splunk_dashboard_create_api_url(namespace),
      'method' => 'POST',
      'vars_get' => {
        'output_mode' => 'json'
      },
      'vars_post' => {
        'name' => name,
        'eai:data' => template,
        'eai:type' => 'views'
      },
      'cookie' => cookie,
      'headers' => {
        'X-Splunk-Form-Key' => csrf,
        'X-Requested-With': 'XMLHttpRequest'
      }
    )
    unless res&.code == 201
      fail_with(Msf::Module::Failure::UnexpectedReply, "#{peer} Server did not respond with the expected HTTP 200")
    end

    res
  end

  # Exports a Splunk dashboard to PDF
  #
  # @param namespace [String] The Splunk namespace where the dashboard resides
  # @param name [String] The name of the dashboard to export
  # @param cookie [String] Valid admin's cookie
  # @return [Rex::Proto::Http::Response] HTTP response object containing the exported PDF
  def export_dashboard(namespace, name, cookie)
    csrf = extract_csrf_token(cookie)

    res = send_request_cgi(
      'uri' => splunk_dashboard_pdf_export_api_url(namespace, name),
      'method' => 'POST',
      'vars_post' => {
        'input-dashboard' => name,
        'namespace' => namespace,
        'splunk_form_key' => csrf
      },
      'cookie' => cookie
    )
    unless res&.code == 200
      fail_with(Msf::Module::Failure::UnexpectedReply, "#{peer} Server did not respond with the expected HTTP 200")
    end

    res
  end

  # Deletes a Splunk dashboard from the specified namespace
  #
  # @param namespace [String] The Splunk namespace where the dashboard resides
  # @param name [String] The name of the dashboard to delete
  # @param cookie [String] Valid admin's cookie
  # @return [Rex::Proto::Http::Response] HTTP response object
  def delete_dashboard(namespace, name, cookie)
    csrf = extract_csrf_token(cookie)

    res = send_request_cgi(
      'uri' => splunk_dashboard_delete_api_url(namespace, name),
      'method' => 'DELETE',
      'vars_get' => {
        'output_mode' => 'json'
      },
      'cookie' => @cookie,
      'headers' => {
        'X-Requested-With': 'XMLHttpRequest',
        'X-Splunk-Form-Key' => csrf
      }
    )
    unless res&.code == 200
      fail_with(Msf::Module::Failure::UnexpectedReply, "#{peer} Server did not respond with the expected HTTP 200")
    end

    res
  end
end
