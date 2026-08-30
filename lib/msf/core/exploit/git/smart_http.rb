# -*- coding: binary -*-

module Msf::Exploit::Git

module SmartHttp

  include Msf::Exploit::Git::PktLine
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super

    register_options([
      Msf::OptString.new('GIT_URI', [ true, 'Git repository path', '' ])
    ])

    register_advanced_options([
      Msf::OptString.new('GitUsername', [ false, 'The Git user name for authentication', '' ]),
      Msf::OptString.new('GitPassword', [ false, 'The Git password for authentication', '' ])
    ])

    @git_agent = agent
  end

  def git_user
    datastore['GitUsername']
  end

  def git_pass
    datastore['GitPassword']
  end

  def server_capabilities(refs)
    caps = "multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since "
    caps << "deepen-not deepen-relative no-progress include-tag multi_ack_detailed allow-tip-sha1-in-want "
    caps << "allow-reachable-sha1-in-want no-done symref=HEAD:#{refs['HEAD']} filter object-format=sha1 "
    caps << "agent=#{@git_agent}"
  end

  def client_capabilities
    "report-status side-band-64k agent=#{@git_agent}"
  end

  def agent
    major = '2'
    minor = Rex::Text.rand_text_numeric(1..2)

    "git/#{major}.#{minor}.#{Rex::Text.rand_text_numeric(1)}"
  end


  # Sends the initial Git request for a Git clone
  #
  # @param [String] the uri to the Git repo
  #
  # @return [Response]
  def send_upload_pack_request(git_uri)
    request_params =
    {
      'method' => 'GET',
      'uri' => normalize_uri(git_uri, 'info/refs'),
      'vars_get' => { 'service' => 'git-upload-pack' }
    }

    send_request_cgi(request_params)
  end

  # Sends a request containing objects client wants
  # to the server
  #
  # @param [String] the uri to the Git repo
  #
  # @return [Response]
  def send_want_request(git_uri, git_objs)
    request_params =
    {
      'method' => 'POST',
      'uri' => normalize_uri(git_uri, 'git-upload-pack'),
      'ctype'  =>  'application/x-git-upload-pack-request',
      'headers' => { 'Accept' =>  'application/x-git-upload-pack-result' },
      'data' => build_pkt_line_want(git_objs)
    }

    send_request_cgi(request_params)
  end

  # Sends the initial Git request for a Git push
  #
  # @param [String] the uri to the Git repo
  #
  # @return [Response]
  def send_ref_discovery_request(git_uri)
    puts 'sending ref discovery request'
    request_params =
    {
      'method' => 'GET',
      'uri' => normalize_uri(git_uri, 'info/refs'),
      'agent' => @git_agent,
      'vars_get' => { 'service' => 'git-receive-pack' }
    }

    response = send_request_cgi(request_params)
    return nil unless response

    return response unless response.code == 401
    if git_user.empty? || git_pass.empty?
      raise ArgumentError, 'Credentials are needed to authenticate to Git server'
    end

    request_params.merge!('authorization' => basic_auth(git_user, git_pass))
    send_request_cgi(request_params)
  end

  # Sends request containing Git objects to push to remote
  # repository
  #
  # @param [String] URI of Git repository to push to
  # @param [String] Name of ref that commits will
  #   be pushed to, ex, refs/heads/master
  # @param [Array] Git objects to push to remote repo
  # @param [String] The branch tip of the remote repository
  #
  # return [Response]
  def send_receive_pack_request(git_uri, ref, objects, branch_tip = '')
    packfile = Packfile.new(nil, objects)
    pkt_line = build_pkt_line_receive_pack(ref, objects, branch_tip)
    data = pkt_line + packfile.data

    request_params =
    {
      'method' => 'POST',
      'uri' => normalize_uri(git_uri, 'git-receive-pack'),
      'authorization' => basic_auth(git_user, git_pass),
      'agent' => @git_agent,
      'ctype'  =>  'application/x-git-receive-pack-request',
      'headers' => { 'Accept' =>  'application/x-git-receive-pack-result' },
      'data' => data
    }

    send_request_cgi(request_params)
  end

  # This will generate a response to a ref discovery
  # request
  #
  # @param [Msf::Exploit::Git::SmartHttp::Request]
  #   request received from Git client
  # @param [Hash] Hash of repo references 
  #
  # @return [Msf::Exploit::Git::SmartHttp::Response]
  #   nil if response cannot be created
  def get_ref_discovery_response(request, refs)
    return nil unless request

    opts = {}
    unless request.type == 'ref-discovery'
      opts[:code] = 403
      opts[:message] = 'Forbidden'
      vprint_error('Invalid request type.')
      return Msf::Exploit::Git::SmartHttp::Response.new(opts)
    end

    resp_body = build_pkt_line_advertise(refs)
    return nil unless resp_body

    opts[:type] = 'ref-discovery'
    response = Msf::Exploit::Git::SmartHttp::Response.new(opts)
    response.body = resp_body

    response
  end

  # This will generate a response to an upload pack 
  # request
  #
  # @param [Msf::Exploit::Git::SmartHttp::Request]
  #   request received from Git client
  # @param [Array] list of Git objects in repo to send
  #
  # @return [Msf::Exploit::Git::SmartHttp::Response]
  #   nil if response cannot be created
  def get_upload_pack_response(request, git_obj_list)
    request.populate_wants_haves
    want_list = request.wants
    return nil if want_list.empty? || git_obj_list.empty?

    opts = {}
    packfile_objs = []
    opts[:type] = 'upload-pack'
    want_list.each do |sha1|
      git_obj_list.each { |git_obj| packfile_objs << git_obj if git_obj.sha1 == sha1 }
    end

    opts[:wants] = packfile_objs
    packfile = Packfile.new(nil, git_obj_list)
    response = Msf::Exploit::Git::SmartHttp::Response.new(opts)
    response.body = build_pkt_line_sideband(packfile)

    response
  end

  private

  # This builds the pkt-line portion of the receive-pack request
  #
  # @param [String] reference name of branch being pushed to
  # @param [Array] List of objects to push to remote repo 
  # @param [String] Optional parameter to specify the branch tip
  #   sha1 in case multiple objects are being pushed
  #
  # @return [String] the pkt-line contents for the request
  def build_pkt_line_receive_pack(ref, objects, branch_tip = '')
    data = ''
    commits = []
    branch_sha = '0' * 40

    objects.each do |obj|
      commits << obj if obj.type == 'commit'
    end

    num_commits = commits.length
    unless num_commits > 0
      raise ArgumentError, 'At least one commit is needed to push to the repo'
    end

    unless branch_tip.empty?
      branch_sha = branch_tip
    end

    pkt_data = "#{branch_sha} #{commits.first.sha1} #{ref}\x00 #{client_capabilities}"
    cmd_pkt =  Msf::Exploit::Git::PktLine.generate_pkt_line(pkt_data)
    data << cmd_pkt
    data << Msf::Exploit::Git::PktLine.generate_pkt_line(nil, type: 'flush-pkt')
  end

  # This constructs the pkt-line portion of a ref discovery
  # request
  #
  # @param [Hash] A hash of the Git repository references
  # https://git-scm.com/docs/http-protocol
  def build_pkt_line_advertise(refs)
    body = ''

    body << Msf::Exploit::Git::PktLine.generate_pkt_line('# service=git-upload-pack')
    if refs.nil? || refs.empty?
      body << Msf::Exploit::Git::PktLine.generate_pkt_line(nil, type: 'flush-pkt')
    else
      body << Msf::Exploit::Git::PktLine.generate_pkt_line(nil, type: 'flush-pkt')

      head_obj = refs[refs['HEAD']]
      unless head_obj
        vprint_error('No HEAD in references supplied')
        return nil
      end
      cap_line = "#{head_obj} HEAD\0#{server_capabilities(refs)}"
      body << Msf::Exploit::Git::PktLine.generate_pkt_line(cap_line)

      refs.each { |key, value| body << Msf::Exploit::Git::PktLine.generate_pkt_line("#{value} #{key}") unless key == 'HEAD' }
    end

    # all responses should be terminated w / flush-pkt
    body << Msf::Exploit::Git::PktLine.generate_pkt_line(nil, type: 'flush-pkt')
  end


  # This constructs the pkt-line portion of a ref discovery
  # request
  #
  # @param [Hash] A hash of the Git repository references
  # https://git-scm.com/docs/http-protocol
  def build_pkt_line_want(wants, capabilities = '')
    body = ''
    def_caps = "multi_ack_detailed no-done side-band-64k thin-pack ofs-delta "
    def_caps << "deepen-since deepen-not agent=#{agent}"
    caps = capabilities || def_caps

    first = wants.first
    body << Msf::Exploit::Git::PktLine.generate_pkt_line("want #{first} #{caps}")
    wants.each do |want|
      next if want == first
      body << Msf::Exploit::Git::PktLine.generate_pkt_line("want #{want}")
    end

    body << Msf::Exploit::Git::PktLine.generate_pkt_line(nil, type: 'flush-pkt')
    body << Msf::Exploit::Git::PktLine.generate_pkt_line('done')
  end

  def build_pkt_line_sideband(packfile)
    obj_count = packfile.git_objects.length

    body = Msf::Exploit::Git::PktLine.generate_pkt_line('NAK')
    body << Msf::Exploit::Git::PktLine.generate_pkt_line("#{[ '2' ].pack('h')}Enumerating objects: #{obj_count}, done.")
    body << Msf::Exploit::Git::PktLine.generate_pkt_line("#{[ '2' ].pack('h')}Counting objects: 100% (#{obj_count}/#{obj_count}), done.")
    body << Msf::Exploit::Git::PktLine.generate_pkt_line("#{[ '2' ].pack('h')}Compressing objects: 100% (#{obj_count}/#{obj_count}), done.")
    body << Msf::Exploit::Git::PktLine.generate_pkt_line("#{[ '1' ].pack('h')}#{packfile.data}")
    body << Msf::Exploit::Git::PktLine.generate_pkt_line("#{[ '2' ].pack('h')}Total #{obj_count} (delta 0), reused 0 (delta 0), pack-reused 0")
    body << Msf::Exploit::Git::PktLine.generate_pkt_line(nil, type: 'flush-pkt')
    
    body
  end

end
end
