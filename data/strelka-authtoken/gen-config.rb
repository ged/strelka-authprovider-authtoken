# -*- ruby -*-
# vim: set nosta noet ts=4 sw=4:
#encoding: utf-8

# The Mongrel config used by the demo app.
#
#   m2sh.rb -c mongrel2.sqlite load data/strelka-authtoken/gen-config.rb
#

require 'strelka'
require 'mongrel2'
require 'mongrel2/config/dsl'

Strelka.load_config( 'data/strelka-authtoken/demo-config.yml' )

# samples server
server 'demo' do

	name         'Strelka AuthToken Demo'
	default_host 'localhost'

	access_log   '/logs/access.log'
	error_log    '/logs/error.log'
	chroot       '/var/mongrel2'
	pid_file     '/run/mongrel2.pid'

	bind_addr    '127.0.0.1'
	port         8118

	host 'localhost' do
		route '/', handler( 'tcp://127.0.0.1:9818', 'authtoken-demo' )
	end

end

setting "zeromq.threads", 1

mkdir_p 'var'
mkdir_p 'run'
mkdir_p 'logs'

