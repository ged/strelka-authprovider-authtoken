# -*- ruby -*-
# vim: set nosta noet ts=4 sw=4:

require 'loggability'
require 'configurability'

require 'strelka' unless defined?( Strelka )
require 'strelka/app' unless defined?( Strelka::App )
require 'strelka/authprovider'
require 'strelka/mixins'
require 'strelka/scscookie'


# AuthToken authentication provider for Strelka applications.
#
# This plugin provides cookie-based authentication using the "SCS: Secure
# Cookie Sessions for HTTP" described in:
#
#   http://tools.ietf.org/html/draft-secure-cookie-session-protocol-04
#
# == Configuration
#
# The configuration for this provider is read from the 'authtoken' section of the config, and
# may contain the following keys:
#
# [realm]::         the 
# [cookie_name]::   a Hash of username: SHA1+Base64'ed passwords
#
# An example:
#
#   --
#   auth:
#     provider: authtoken
#
class Strelka::AuthProvider::AuthToken < Strelka::AuthProvider
	extend Loggability,
	       Configurability,
	       Strelka::MethodUtilities
	include Strelka::Constants

	# Configurability API - set the section of the config
	config_key :authtoken


	# Library version constant
	VERSION = '0.0.1'

	# Version-control revision constant
	REVISION = %q$Revision$


	# Default configuration
	CONFIG_DEFAULTS = {
		cookie_name:  'strelka-authtoken',
		realm:        nil,
	}.freeze


	##
	# The name of the cookie used for the authentication token
	singleton_attr_accessor :cookie_name
	@cookie_name = CONFIG_DEFAULTS[:cookie_name]

	##
	# The authentication realm
	singleton_attr_accessor :realm
	@realm = CONFIG_DEFAULTS[:realm]


	### Configurability API -- configure the auth provider instance.
	def self::configure( config=nil )
		config ||= {}

		self.log.debug "Configuring AuthToken authprovider: %p" % [ config ]
		self.cookie_name  = config[:cookie_name] || CONFIG_DEFAULTS[:cookie_name]
		self.realm        = config[:realm]       || CONFIG_DEFAULTS[:realm]
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

	end


	######
	public
	######

	### Check the authentication present in +request+ (if any) for validity, returning the
	### authenticating user's name if authentication succeeds.
	def authenticate( request )
		Strelka::SCSCookie.rotate_keys
		return self.check_for_auth_cookie( request )
	end


	### Add a authtoken cookie for +username+ to the response for the given +request+ when auth
	### succeeds.
	def auth_succeeded( request, username )

		# Add the token to the response
		# self.log.debug "Adding an SCS cookie for %p to the response." % [ username ]
		cookie = Strelka::SCSCookie.new( self.class.cookie_name, username )
		request.response.cookies << cookie
	end


	### Extract credentials from the given request and validate them, either via a
	### valid authentication token, or from request parameters.
	def check_for_auth_cookie( request )
		# self.log.debug "Checking for an auth cookie."
		cookie = request.cookies[ self.class.cookie_name ] or
			log_failure "No auth cookie: %s" % [ self.class.cookie_name ]

		# self.log.debug "  upgrading the regular cookie to an SCSCookie."
		scs_cookie = Strelka::SCSCookie.from_regular_cookie( cookie ) or
			log_failure "Couldn't upgrade the %s cookie to SCS" % [ self.class.cookie_name]

		# self.log.debug "  setting the %s cookie to %p" % [ self.class.cookie_name, scs_cookie ]
		request.cookies[ self.class.cookie_name ] = scs_cookie

		# self.log.debug "  returning authenticated username: %p" % [ scs_cookie.value ]
		return scs_cookie.value
	end


	#########
	protected
	#########

	### Syntax sugar to allow returning 'false' while logging a reason for doing so.
	### Log a message at 'info' level and return false.
	def log_failure( reason )
		self.log.warn "Auth failure: %s" % [ reason ]
		header = "AuthToken realm=%s" % [ self.class.realm ]
		finish_with( HTTP::AUTH_REQUIRED, "Requires authentication.", www_authenticate: header )
	end

end # class Strelka::AuthProvider::Basic
