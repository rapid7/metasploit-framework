require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteNoteDataService
  include ResponseDataHelper

  NOTE_API_PATH = '/api/v1/notes'

  def report_note(opts)
    self.post_data_async(NOTE_API_PATH, opts)
  end
end