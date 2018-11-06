#!/usr/bin/env ruby -I ../lib -I lib
require 'sinatra'
get('/') { 'this is a simple app' }
