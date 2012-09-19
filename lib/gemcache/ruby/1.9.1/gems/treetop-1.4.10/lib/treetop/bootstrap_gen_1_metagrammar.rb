# This file's job is to load a Treetop::Compiler::Metagrammar and Treetop::Compiler::MetagrammarParser
# into the environment by compiling the current metagrammar.treetop using a trusted version of Treetop.

require 'rubygems'

TREETOP_VERSION_REQUIRED_TO_BOOTSTRAP = '>= 1.1.5'

# Loading trusted version of Treetop to compile the compiler
gem_spec = Gem.source_index.find_name('treetop', TREETOP_VERSION_REQUIRED_TO_BOOTSTRAP).last
raise "Install a Treetop Gem version #{TREETOP_VERSION_REQUIRED_TO_BOOTSTRAP} to bootstrap." unless gem_spec
require "#{gem_spec.full_gem_path}/lib/treetop"

# Relocating trusted version of Treetop to Trusted::Treetop
Trusted = Module.new
Trusted::Treetop = Treetop
Object.send(:remove_const, :Treetop)

# Requiring version of Treetop that is under test
$exclude_metagrammar = true
require File.expand_path('../treetop')

# Compile and evaluate freshly generated metagrammar source
METAGRAMMAR_PATH = File.expand_path('../compiler/metagrammar.treetop', __FILE__)
compiled_metagrammar_source = Trusted::Treetop::Compiler::GrammarCompiler.new.ruby_source(METAGRAMMAR_PATH)
Object.class_eval(compiled_metagrammar_source)

# The compiler under test was compiled with the trusted grammar and therefore depends on its runtime
# But the runtime in the global namespace is the new runtime. We therefore inject the trusted runtime
# into the compiler so its parser functions correctly. It will still not work for custom classes that
# explicitly subclass the wrong runtime. For now I am working around this by keeping 1 generation of
# backward compatibility in these cases.
# Treetop::Compiler::Metagrammar.module_eval do
#   include Trusted::Treetop::Runtime
# end
# 
# Treetop::Compiler.send(:remove_const, :MetagrammarParser)
# class Treetop::Compiler::MetagrammarParser < Trusted::Treetop::Runtime::CompiledParser
#   include Treetop::Compiler::Metagrammar
#   include Trusted::Treetop::Runtime
# end

$bootstrapped_gen_1_metagrammar = true
