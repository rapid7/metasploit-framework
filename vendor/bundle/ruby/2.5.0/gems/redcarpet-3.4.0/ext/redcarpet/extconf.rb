require 'mkmf'

$CFLAGS << ' -fvisibility=hidden'

dir_config('redcarpet')
create_makefile('redcarpet')
