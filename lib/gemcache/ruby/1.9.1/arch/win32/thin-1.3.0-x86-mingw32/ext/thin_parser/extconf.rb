require 'mkmf'

dir_config("thin_parser")
have_library("c", "main")

create_makefile("thin_parser")
