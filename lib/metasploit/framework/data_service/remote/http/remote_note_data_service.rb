require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteNoteDataService
  include ResponseDataHelper

  NOTE_API_PATH = '/api/1/msf/note'

  def report_note(opts)
    self.post_data_async(NOTE_API_PATH, opts)
  end
end