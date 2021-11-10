module Msf::DBManager::Note
  include InitializeNotes
  #
  # This method iterates the notes table calling the supplied block with the
  # note instance of each entry.
  #
  def each_note(wspace=framework.db.workspace, &block)
  ::ApplicationRecord.connection_pool.with_connection {
    wspace.notes.each do |note|
      block.call(note)
    end
  }
  end

  #
  # Find or create a note matching this type/data
  #
  def find_or_create_note(opts)
    report_note(opts)
  end

  #
  # This methods returns a list of all notes in the database
  #
  def notes(opts)
    ::ApplicationRecord.connection_pool.with_connection {
      # If we have the ID, there is no point in creating a complex query.
      if opts[:id] && !opts[:id].to_s.empty?
        return Array.wrap(Mdm::Note.find(opts[:id]))
      end

      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework)
      opts = opts.clone()
      opts.delete(:workspace)

      data = opts.delete(:data)
      search_term = opts.delete(:search_term)
      results = wspace.notes.includes(:host).where(opts)

      # Compare the deserialized data from the DB to the search data since the column is serialized.
      unless data.nil?
        results = results.select { |note| note.data == data }
      end

      if search_term && !search_term.empty?
        re_search_term = /#{search_term}/mi
        results = results.select { |note|
          note.attribute_names.any? { |a| note[a.intern].to_s.match(re_search_term) }
        }
      end
      results
    }
  end

  #
  # Report a Note to the database.  Notes can be tied to a ::Mdm::Workspace, Host, or Service.
  #
  # opts MUST contain
  # +:type+::  The type of note, e.g. smb_peer_os
  #
  # opts can contain
  # +:workspace+::  the workspace to associate with this Note
  # +:host+::       an IP address or a Host object to associate with this Note
  # +:service+::    a Service object to associate with this Note
  # +:data+::       whatever it is you're making a note of
  # +:port+::       along with +:host+ and +:proto+, a service to associate with this Note
  # +:proto+::      along with +:host+ and +:port+, a service to associate with this Note
  # +:update+::     what to do in case a similar Note exists, see below
  #
  # The +:update+ option can have the following values:
  # +:unique+::       allow only a single Note per +:host+/+:type+ pair
  # +:unique_data+::  like +:uniqe+, but also compare +:data+
  # +:insert+::       always insert a new Note even if one with identical values exists
  #
  # If the provided +:host+ is an IP address and does not exist in the
  # database, it will be created.  If +:workspace+, +:host+ and +:service+
  # are all omitted, the new Note will be associated with the current
  # workspace.
  #
  def report_note(opts)
    return if not active
    ::ApplicationRecord.connection_pool.with_connection {
      note = initialize_note(opts)
      ret = {}
      note.save!
      ret[:note] = note
    }
  end

  # Update the attributes of a note entry with the values in opts.
  # The values in opts should match the attributes to update.
  #
  # @param opts [Hash] Hash containing the updated values. Key should match the attribute to update. Must contain :id of record to update.
  # @return [Mdm::Note] The updated Mdm::Note object.
  def update_note(opts)
    ::ApplicationRecord.connection_pool.with_connection {
      wspace = Msf::Util::DBManager.process_opts_workspace(opts, framework, false)
      opts = opts.clone()
      opts.delete(:workspace)
      opts[:workspace] = wspace if wspace

      id = opts.delete(:id)
      note = Mdm::Note.find(id)
      note.update!(opts)
      return note
    }
  end

  # Deletes note entries based on the IDs passed in.
  #
  # @param opts[:ids] [Array] Array containing Integers corresponding to the IDs of the note entries to delete.
  # @return [Array] Array containing the Mdm::Note objects that were successfully deleted.
  def delete_note(opts)
    raise ArgumentError.new("The following options are required: :ids") if opts[:ids].nil?

    ::ApplicationRecord.connection_pool.with_connection {
      deleted = []
      opts[:ids].each do |note_id|
        note = Mdm::Note.find(note_id)
        begin
          deleted << note.destroy
        rescue # refs suck
          elog("Forcibly deleting #{note}")
          deleted << note.delete
        end
      end

      return deleted
    }
  end
end
