# frozen_string_literal: true
require 'ostruct'

include Server
include Commands

def mock_adapter(opts = {})
  opts[:libraries] ||= {'project' => [LibraryVersion.new('project', '1.0.0'), LibraryVersion.new('project', '1.0.1')]}
  opts[:document_root] ||= '/public'
  opts[:options] ||= {:single_library => false, :caching => false}
  opts[:server_options] ||= {}
  OpenStruct.new(opts)
end

class MockRequest < OpenStruct
  def path; "#{script_name}#{path_info}" end
end

def mock_request(path_info = '/', script_name = '', extra_env = {})
  opts = {:path_info => path_info, :script_name => script_name}
  MockRequest.new(extra_env.merge(opts))
end
