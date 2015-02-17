require 'pathname'

support = Pathname.new(__FILE__).realpath.parent

paths = [
    # adds support/bin at the front of the path so that the support/bin/stty script will be used to fake system stty
    # output.
    support.join('bin').to_path,
    ENV['PATH']
]
ENV['PATH'] = paths.join(File::PATH_SEPARATOR)
