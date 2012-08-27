# -*- ruby -*-
# vim: set nosta noet ts=4 sw=4:

require 'loggability'
require 'configurability'

require 'strelka' unless defined?( Strelka )
require 'strelka/app' unless defined?( Strelka::App )
require 'strelka/authprovider'
require 'strelka/mixins'

# AuthToken authentication provider for Strelka applications.
#
# This plugin provides cookie-based authentication using the "Secure Cookie Protocol"
# described in:
#
#   http://www.cse.msu.edu/~alexliu/publications/Cookie/cookie.pdf
#
# == Configuration
#
# The configuration for this provider is read from the 'auth' section of the config, and
# may contain the following keys:
#
# [users]::   a Hash of username: SHA1+Base64'ed passwords
#
# An example:
#
#   --
#   auth:
#     realm: Acme Admin Console
#     users:
#       mgranger: "9d5lIumnMJXmVT/34QrMuyj+p0E="
#       jblack: "1pAnQNSVtpL1z88QwXV4sG8NMP8="
#       kmurgen: "MZj9+VhZ8C9+aJhmwp+kWBL76Vs="
#
class Strelka::AuthProvider::Basic < Strelka::AuthProvider
	extend Loggability,
	       Configurability,
	       Strelka::MethodUtilities
	include Strelka::Constants

	# Configurability API - set the section of the config
	config_key :auth


	@users = nil
	@realm = nil

	##
	# The Hash of users and their SHA1+Base64'ed passwords
	singleton_attr_accessor :users

	##
	# The authentication realm
	singleton_attr_accessor :realm


	### Configurability API -- configure the auth provider instance.
	def self::configure( config=nil )
		if config
			self.log.debug "Configuring Basic authprovider: %p" % [ config ]
			self.realm = config['realm'] if config['realm']
			self.users = config['users'] if config['users']
		else
			self.realm = nil
			self.users = {}
		end
	end


	#################################################################
	###	I N S T A N C E   M E T H O D S
	#################################################################

	### Create a new Default AuthProvider.
	def initialize( * )
		super

		# Default the authentication realm to the application's ID
		unless self.class.realm
			self.log.warn "No realm configured -- using the app id"
			self.class.realm = self.app.conn.app_id
		end

		unless self.class.users
			self.log.warn "No users configured -- using an empty user list"
			self.class.users = {}
		end
	end


	######
	public
	######

	# Check the authentication present in +request+ (if any) for validity, returning the
	# authenticating user's name if authentication succeeds.
	def authenticate( request )
		authheader = request.header.authorization or
			self.log_failure "No authorization header in the request."

		# Extract the credentials bit
		base64_userpass = authheader[ /^\s*Basic\s+(\S+)$/i, 1 ] or
			self.log_failure "Invalid Basic Authorization header (%p)" % [ authheader ]

		# Unpack the username and password
		credentials = base64_userpass.unpack( 'm' ).first
		self.log_failure "Malformed credentials %p" % [ credentials ] unless
			credentials.index(':')

		# Split the credentials, check for valid user
		username, password = credentials.split( ':', 2 )
		digest = self.class.users[ username ] or
			self.log_failure "No such user %p." % [ username ]

		# Fail if the password's hash doesn't match
		self.log_failure "Password mismatch." unless
			digest == Digest::SHA1.base64digest( password )

		# Success!
		self.log.info "Authentication for %p succeeded." % [ username ]
		return username
	end


	#########
	protected
	#########

	### Syntax sugar to allow returning 'false' while logging a reason for doing so.
	### Log a message at 'info' level and return false.
	def log_failure( reason )
		self.log.warn "Auth failure: %s" % [ reason ]
		header = "Basic realm=%s" % [ self.class.realm ]
		finish_with( HTTP::AUTH_REQUIRED, "Requires authentication.", www_authenticate: header )
	end

end # class Strelka::AuthProvider::Basic
