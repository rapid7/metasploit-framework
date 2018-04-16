module NoteDataService

  def notes(opts)
    raise NotImplementedError, 'NoteDataService#notes is not implemented'
  end

  def report_note(opts)
    raise NotImplementedError, 'NoteDataService#report_note is not implemented'
  end

  def update_note(opts)
    raise NotImplementedError, 'NoteDataService#update_note is not implemented'
  end

  def delete_note(opts)
    raise NotImplementedError, 'NoteDataService#delete_note is not implemented'
  end

end