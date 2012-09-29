# -*- ruby -*-
# vim: set nosta noet ts=4 sw=4:
#encoding: utf-8

# The Mongrel config used by the demo app.
#
#   m2sh.rb -c example/mongrel2.sqlite load example/gen-config.rb
#


# samples server
server 'demo' do

	name         'Strelka AuthToken Demo'
	default_host 'localhost'

	chroot       '.'
	access_log   '/logs/access.log'
	error_log    '/logs/error.log'
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

