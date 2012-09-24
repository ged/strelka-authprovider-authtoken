#!/usr/bin/ruby
# coding: utf-8

BEGIN {
	require 'pathname'
	basedir = Pathname.new( __FILE__ ).dirname.parent.parent

	srcdir = basedir.parent
	libdir = basedir + "lib"

	$LOAD_PATH.unshift( basedir.to_s ) unless $LOAD_PATH.include?( basedir.to_s )
	$LOAD_PATH.unshift( libdir.to_s ) unless $LOAD_PATH.include?( libdir.to_s )
}

# SimpleCov test coverage reporting; enable this using the :coverage rake task
if ENV['COVERAGE']
	$stderr.puts "\n\n>>> Enabling coverage report.\n\n"
	require 'simplecov'
	SimpleCov.start do
		add_filter 'spec'
		add_group "Needing tests" do |file|
			file.covered_percent < 90
		end
	end
end

require 'loggability'
require 'loggability/spechelpers'
require 'configurability'

require 'rspec'
require 'mongrel2'
require 'mongrel2/testing'

require 'strelka'
require 'strelka/testing'
require 'strelka/authprovider'
require 'strelka/authprovider/authtoken'


Loggability.format_with( :color ) if $stdout.tty?


### RSpec helper functions.
module SpecHelpers
end

abort "You need a version of RSpec >= 2.6.0" unless defined?( RSpec )

### Mock with RSpec
RSpec.configure do |c|
	include Strelka::Constants

	c.mock_with( :rspec )
	c.treat_symbols_as_metadata_keys_with_true_values = true

	c.include( Loggability::SpecHelpers )
	c.include( Mongrel2::SpecHelpers )
	c.include( Strelka::Constants )
	c.include( Strelka::Testing )
	c.include( SpecHelpers )
end

# vim: set nosta noet ts=4 sw=4:

