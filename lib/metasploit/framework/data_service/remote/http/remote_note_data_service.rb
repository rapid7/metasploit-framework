require 'metasploit/framework/data_service/remote/http/response_data_helper'

module RemoteNoteDataService
  include ResponseDataHelper

  NOTE_API_PATH = '/api/v1/notes'
  NOTE_MDM_CLASS = 'Mdm::Note'

  def notes(opts)
    path = get_path_select(opts, NOTE_API_PATH)
    json_to_mdm_object(self.get_data(path, nil, opts), NOTE_MDM_CLASS)
  end

  def report_note(opts)
    json_to_mdm_object(self.post_data(NOTE_API_PATH, opts), NOTE_MDM_CLASS).first
  end

  def update_note(opts)
    path = NOTE_API_PATH
    if opts && opts[:id]
      id = opts.delete(:id)
      path = "#{NOTE_API_PATH}/#{id}"
    end
    json_to_mdm_object(self.put_data(path, opts), NOTE_MDM_CLASS)
  end

  def delete_note(opts)
    json_to_mdm_object(self.delete_data(NOTE_API_PATH, opts), NOTE_MDM_CLASS)
  end
end