# -*- coding: binary -*-

module Msf
  ###
  #
  # This module provides methods for brute forcing authentication
  #
  ###

  module Auxiliary::Web
    module Analysis
    end

    require 'msf/core/auxiliary/web/http'
    require 'msf/core/auxiliary/web/fuzzable'
    require 'msf/core/auxiliary/web/form'
    require 'msf/core/auxiliary/web/path'
    require 'msf/core/auxiliary/web/target'

    include Auxiliary::Report

    attr_reader :target
    attr_reader :http
    attr_reader :parent
    attr_reader :page

    def initialize(info = {})
      super
    end

    # String id to push to the #checklist
    def checked(id)
      parent.checklist << "#{shortname}#{id}".hash
    end

    # String id to check against the #checklist
    def checked?(id)
      parent.checklist.include? "#{shortname}#{id}".hash
    end

    #
    # Called directly before 'run'
    #
    def setup(opts = {})
      @parent = opts[:parent]
      @target = opts[:target]
      @page   = opts[:page]
      @http   = opts[:http]
    end

    # Should be overridden to return the exploits to use for this
    # vulnerability type as an Array of Strings.
    def self.exploits; end

    # Must return a configuration Hash for the given exploit and vulnerability.
    def self.configure_exploit(exploit, vuln); end

    # Should be overridden to return the payloads used for this
    # vulnerability type as an Array of Strings.
    def payloads; end

    def token
      "xssmsfpro"
    end

    #
    # Should be overridden to return a pattern to be matched against response
    # bodies in order to identify a vulnerability.
    #
    # You can go one deeper and override #find_proof for more complex processing.
    #
    def signature; end

    #
    # Default #run, will audit all elements using taint analysis and log
    # results based on #find_proof return values.
    #
    def run
      auditable.each(&:taint_analysis)
    end

    # Returns an Array of elements prepared to be audited.
    def auditable
      target.auditable.map do |element|
        element.fuzzer = self
        element
      end
    end

    # Checks whether a resource exists based on a path String.
    def resource_exist?(path)
      res = http.get(path)
      res.code.to_i == 200 && !http.custom_404?(path, res.body)
    end
    alias file_exist? resource_exist?

    # Checks whether a directory exists based on a path String.
    def directory_exist?(path)
      dir = path.dup
      dir << '/' if !dir.end_with?('/')
      resource_exist?(dir)
    end

    # Logs the existence of a resource in the path String.
    def log_resource_if_exists(path)
      log_resource(location: path) if resource_exist?(path)
    end
    alias log_file_if_exists log_resource_if_exists

    # Logs the existence of the directory in the path String.
    def log_directory_if_exists(path)
      dir = path.dup
      dir << '/' if !dir.end_with?('/')
      log_resource_if_exists(dir)
    end

    # Matches fingerprint pattern against the current page's body and logs matches
    def match_and_log_fingerprint(fingerprint, options = {})
      return if (match = page.body.to_s.match(fingerprint).to_s).empty?
      log_fingerprint(options.merge(fingerprint: match))
    end

    #
    # Serves as a default detection method for when performing taint analysis.
    #
    # Uses the Regexp in #signature against the response body in order to
    # identify vulnerabilities and return a String that proves it.
    #
    # Override it if you need more complex processing, but remember to return
    # the proof as a String.
    #
    # response - Auxiliary::Web::HTTP::Response
    # element - the submitted element
    #
    def find_proof(response, _element)
      return if !signature

      m = response.body.match(signature).to_s
      return if !m || m.empty?

      m.gsub(/[\r\n]/, ' ')
    end

    def increment_request_counter
      parent.increment_request_counter
    end

    # Should be overridden and return an Integer (0-100) denoting the confidence
    # in the accuracy of the logged vuln.
    def calculate_confidence(_vuln)
      100
    end

    def log_fingerprint(opts = {})
      mode  = name
      vhash = [target.to_url, opts[:fingerprint], mode, opts[:location]]
              .map(&:to_s).join('|').hash

      parent.vulns[mode] ||= {}
      return if parent.vulns[mode].include?(vhash)

      location = opts[:location] ?
        page.url.merge(URI(opts[:location].to_s)) : page.url

      info = {
        web_site: target.site,
        path: location.path,
        query: location.query,
        method: 'GET',
        params: [],
        pname: 'path',
        proof: opts[:fingerprint],
        risk: details[:risk],
        name: details[:name],
        blame: details[:blame],
        category: details[:category],
        description: details[:description],
        owner: self
      }

      info[:confidence] = calculate_confidence(info)
      parent.vulns[mode][vhash] = info

      report_web_vuln(info)

      opts[:print_fingerprint] = true if !opts.include?(:print_fingerprint)

      print_good "	FOUND(#{mode}) URL(#{location})"
      print_good "		 PROOF(#{opts[:fingerprint]})" if opts[:print_fingerprint]
    end

    def log_resource(opts = {})
      mode  = name
      vhash = [target.to_url, mode, opts[:location]]
              .map(&:to_s).join('|').hash

      parent.vulns[mode] ||= {}
      return if parent.vulns[mode].include?(vhash)

      location = URI(opts[:location].to_s)
      info = {
        web_site: target.site,
        path: location.path,
        query: location.query,
        method: 'GET',
        params: [],
        pname: 'path',
        proof: opts[:location],
        risk: details[:risk],
        name: details[:name],
        blame: details[:blame],
        category: details[:category],
        description: details[:description],
        owner: self
      }

      info[:confidence] = calculate_confidence(info)
      parent.vulns[mode][vhash] = info

      report_web_vuln(info)

      print_good "	VULNERABLE(#{mode}) URL(#{target.to_url})"
      print_good "		 PROOF(#{opts[:location]})"
    end

    def process_vulnerability(element, proof, opts = {})
      mode  = name
      vhash = [target.to_url, mode, element.altered]
              .map(&:to_s).join('|').hash

      parent.vulns[mode] ||= {}
      return parent.vulns[mode][vhash] if parent.vulns[mode][vhash]

      parent.vulns[mode][vhash] = {
        target: target,
        method: element.method.to_s.upcase,
        params: element.params.to_a,
        mode: mode,
        pname: element.altered,
        proof: proof.to_s,
        form: element.model,
        risk: details[:risk],
        name: details[:name],
        blame: details[:blame],
        category: details[:category],
        description: details[:description]
      }

      confidence = calculate_confidence(parent.vulns[mode][vhash])

      parent.vulns[mode][vhash][:confidence] = confidence

      if !(payload = opts[:payload])
        if payloads
          payload = payloads.select do |p|
            element.altered_value.include?(p)
          end.max_by(&:size)
        end
      end

      uri = URI(element.action)
      info = {
        web_site: element.model.web_site,
        path: uri.path,
        query: uri.query,
        method: element.method.to_s.upcase,
        params: element.params.to_a,
        pname: element.altered,
        proof: proof.to_s,
        risk: details[:risk],
        name: details[:name],
        blame: details[:blame],
        category: details[:category],
        description: details[:description],
        confidence: confidence,
        payload: payload,
        owner: self
      }

      report_web_vuln(info)

      print_good "	VULNERABLE(#{mode}) URL(#{target.to_url})" \
                 " PARAMETER(#{element.altered}) VALUES(#{element.params})"
      print_good "		 PROOF(#{proof})"
    end
    end
end
