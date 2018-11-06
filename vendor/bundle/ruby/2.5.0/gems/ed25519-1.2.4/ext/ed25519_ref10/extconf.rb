# frozen_string_literal: true

# rubocop:disable Style/GlobalVars

require "mkmf"

$CFLAGS << " -Wall -O3 -pedantic -std=c99"

create_makefile "ed25519_ref10"
