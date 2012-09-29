# -*- ruby -*-
# vim: set nosta noet ts=4 sw=4:

require 'uri'
require 'openssl'
require 'zlib'

require 'strelka' unless defined?( Strelka )
require 'strelka/cookie'
require 'strelka/mixins'

# A Cookie that is encoded using SCS: Secure Cookie Sessions for HTTP
#
#   http://tools.ietf.org/html/draft-secure-cookie-session-protocol-06
#
class Strelka::SCSCookie < Strelka::Cookie
	extend Configurability,
	       Strelka::MethodUtilities


	# Configure using the 'scs' section
	config_key :scs


	# The maximum size of the transform ID
	SCS_TID_MAX  = 64

	# A structure for storing keysets
	KeySet = Struct.new( 'Strelka_SCSCookie_Keyset', :tid, :key, :hkey, :expires )


	# Configurability
	CONFIG_DEFAULTS = {
		cipher_type:     'aes-128-cbc',
		digest_type:     'sha1',
		block_size:      16,
		framing_byte:    '|',
		max_session_age: 3600,
		compression:     false,
	}


	#
	# :section: Configuration
	#

	##
	# The cipher to use for encrypting the cookie data
	singleton_attr_reader :cipher_type
	@cipher_type = CONFIG_DEFAULTS[:cipher_type]

	##
	# The digest algorithm to use for the message authentication
	singleton_attr_reader :digest_type
	@digest_type = CONFIG_DEFAULTS[:digest_type]

	##
	# Number of bytes to use for the IV
	singleton_attr_accessor :block_size
	@block_size = CONFIG_DEFAULTS[:block_size]

	##
	# The explicit framing byte used to concatenate the parts of the authtag
	singleton_attr_accessor :framing_byte
	@framing_byte = CONFIG_DEFAULTS[:framing_byte]

	##
	# The maximum number of seconds a session is valid for
	singleton_attr_accessor :max_session_age
	@max_session_age = CONFIG_DEFAULTS[:max_session_age]

	##
	# If true, compress the payload of the cookie before encypting it
	singleton_attr_accessor :compression
	@compression = CONFIG_DEFAULTS[:compression]


	### Set the cipher_type to +cipher+, resetting the current keyset if necessary.
	def self::cipher_type=( cipher )
		if @cipher_type && cipher != @cipher_type
			self.log.warn "Cipher changed; resetting keysets."
			@current_keyset = nil
			@last_keyset = nil
		end

		@cipher_type = cipher
	end


	### Set the digest_type to +digest+, resetting the current keyset if necessary.
	def self::digest_type=( digest )
		if @digest_type && digest != @digest_type
			self.log.warn "Digest changed; resetting keysets."
			@current_keyset = nil
			@last_keyset = nil
		end

		@digest_type = digest
	end


	### Configurability API -- configure the class when the config is loaded.
	def self::configure( config=nil )
		config ||= {}

		self.cipher_type     = config[:cipher_type]     || CONFIG_DEFAULTS[:cipher_type]
		self.digest_type     = config[:digest_type]     || CONFIG_DEFAULTS[:digest_type]
		self.block_size      = config[:block_size]      || CONFIG_DEFAULTS[:block_size]
		self.framing_byte    = config[:framing_byte]    || CONFIG_DEFAULTS[:framing_byte]
		self.max_session_age = config[:max_session_age] || CONFIG_DEFAULTS[:max_session_age]
		self.compression     = config[:compression]     || CONFIG_DEFAULTS[:compression]

		self.log.info "Configured: cipher: %s, digest: %s, blksize: %d, framebyte: %p, maxage: %ds, compression: %s" % [
			self.cipher_type,
			self.digest_type,
			self.block_size,
			self.framing_byte,
			self.max_session_age,
			self.compression
		]

		raise "The %p cipher is not implemented by your OpenSSL implementation" unless
			OpenSSL::Cipher.ciphers.include?( self.cipher_type )
	end


	#
	# :section: Keyset Management
	#

	##
	# A KeySet used for creating auth tokens
	@current_keyset = nil

	##
	# The most-recent expired keyset, used to validate cookies after the keyset has been
	# rotated.
	singleton_attr_reader :last_keyset
	@last_keyset = nil


	### Return the current keyset, creating one if necessary.
	def self::current_keyset
		@current_keyset ||= self.make_new_keyset( self.max_session_age )
		return @current_keyset
	end


	### Set the current keyset to +keyset+.
	def self::current_keyset=( keyset )
		unless keyset.nil?
			self.last_keyset = self.current_keyset
			self.log.info "Activating keyset %s; expires on %s" %
				[ keyset.tid.unpack('H*').join, keyset.expires ]
		end
		@current_keyset = keyset
	end


	### Writer: set the most-recently-expired keyset to +keyset+.
	def self::last_keyset=( keyset )
		self.log.info "Rotating keysets: %s expired on %s" %
			[ keyset.tid.unpack('H*').join, keyset.expires ] unless keyset.nil?
		@last_keyset = keyset
	end


	### Expire the current key and generate a new one if the current keyset is expired.
	def self::rotate_keys
		# self.log.debug "Checking for expired keyset: %s" % [ self.current_keyset.expires ]
		return unless self.current_keyset.expires <= Time.now
		self.current_keyset = Strelka::SCSCookie.make_new_keyset( self.max_session_age )
	end


	### Find the keyset associated with the given +tid+, either the current one
	### or the most-recently-expired one. Return +nil+ if neither of the
	### keysets' TIDs match.
	def self::find_keyset( tid )
		# self.log.debug "Finding keyset for TID: %s" % [ tid.unpack('H*').join ]
		return [ self.current_keyset, self.last_keyset ].compact.find {|ks| ks.tid == tid }
	end


	### Create a new keyset with its expiration set to +expires_at+, which can
	### be a Time object, or an Integer (in which case its treated as the number of
	### seconds until it expires).
	def self::make_new_keyset( expires_at )
		expires_at = Time.now + expires_at unless expires_at.is_a?( Time )
		# self.log.debug "Making a new keyset that expires on %s" % [ expires_at ]

		ks         = KeySet.new
		ks.tid     = self.make_new_tid
		ks.key     = self.make_new_key
		ks.hkey    = self.make_new_hkey
		ks.expires = expires_at

		# self.log.debug "  created keyset %s" % [ ks.tid.unpack('H*').join ]
		return ks
	end


	#
	# :section: Crypto/Compression/Encoding
	#

	### Create and return an instance of the configured OpenSSL::Cipher.
	def self::make_cipher
		shortname = self.cipher_type
		return OpenSSL::Cipher.new( shortname )
	end


	### Create and return an instance of the OpenSSL::Digest.
	def self::make_digest
		shortname = self.digest_type
		return OpenSSL::Digest.new( shortname )
	end


	### Make a new key to use for encryption.
	def self::make_new_key
		key_size = self.make_cipher.key_len
		return OpenSSL::Random.random_bytes( key_size )
	end


	### Make a new key to use for the HMAC.
	def self::make_new_hkey
		key_size = self.make_digest.size
		return OpenSSL::Random.random_bytes( key_size )
	end


	### Generate a new transform ID of the specified +size+.
	def self::make_new_tid
		size = [ self.block_size, SCS_TID_MAX ].min
		data = OpenSSL::Random.random_bytes( size )
		# Shift bytes into visible ASCII:
		#   http://goo.gl/8QIVE
		return data.bytes.collect {|byte| (byte % 93) + 33 }.pack( 'C*' )
	end


	### Encrypt the specified +data+ using the specified +key+ and +iv+.
	def self::encrypt( data, iv, key )
		cipher = self.make_cipher
		cipher.encrypt
		cipher.key = key
		cipher.iv = iv

		encrypted = cipher.update( data ) << cipher.final

		return encrypted
	end


	### Decrypt the specified +data+ using the given +key+ and +iv+.
	def self::decrypt( data, iv, key )
		cipher = self.make_cipher
		cipher.decrypt
		cipher.key = key
		cipher.iv = iv

		decrypted = cipher.update( data ) << cipher.final

		return decrypted
	end


	### Encode the cookie value as Base-64
	def self::encode( value )
		return [ value ].pack( 'm' ).chomp
	end


	### Decode the given +data+ using Base-64 and return the decoded value.
	def self::decode( data )
		return data.unpack( 'm' ).first
	end


	### Compress the specified +data+ and return it.
	def self::compress( data )
		return Zlib::Deflate.deflate( data )
	end


	### Demompress the specified +data+ and return it.
	def self::decompress( data )
		return Zlib::Inflate.inflate( data )
	end


	#
	# :section:
	#

	### Turn a regular +cookie+ into an SCSCookie.
	def self::from_regular_cookie( cookie )
		# self.log.debug "Upgrading cookie %p to a %p" % [ cookie, self ]

		# First of all, the inbound scs-cookie-value is broken into its
		# component fields which MUST be exactly 5, and each at least of the
		# minimum length specified in Figure 1 (step 0.).  In case any of these
		# preliminary checks fails, the PDU is discarded (step 13.); else TID
		# is decoded to allow key-set lookup (step 1.).
		encoded_fields = cookie.value.split( self.framing_byte )
		self.log.debug "  split into fields: %p" % [ encoded_fields ]
		unless encoded_fields.length == 5
			self.log.error "Invalid SCS cookie: expected 5 fields, got %d" % [ encoded_fields.length ]
			return nil
		end
		data, atime, tid, iv, authtag = encoded_fields.collect {|f| f.unpack('m').first }
		# self.log.debug "  decoded fields: %p" % [[ data, atime, tid, iv, authtag ]]

		# If the cryptographic credentials (encryption and authentication
		# algorithms and keys identified by TID) are unavailable (step 12.),
		# the inbound SCS cookie is discarded since its value has no chance to
		# be interpreted correctly.  This may happen for several reasons: e.g.,
		# if a device without storage has been reset and loses the credentials
		# stored in RAM, if a server pool node desynchronizes, or in case of a
		# key compromise that forces the invalidation of all current TID's,
		# etc.
		unless keyset = self.find_keyset( tid )
			self.log.error "Couldn't find keyset for TID %s; expired?" % [ tid.unpack('H*').join ]
			return nil
		end

		# When a valid key-set is found (step 2.), the AUTHTAG field is decoded
		# (step 3.) and the (still) encoded DATA, ATIME, TID and IV fields are
		# supplied to the primitive that computes the authentication tag (step
		# 4.).
		#
		# If the tag computed using the local key-set matches the one carried
		# by the supplied SCS cookie, we can be confident that the cookie
		# carries authentic material; otherwise the SCS cookie is discarded
		# (step 11.).
		cookie_authtag = self.make_authtag( data, atime, iv, keyset )
		# self.log.debug "  challenge authtag is: %p" % [ cookie_authtag ]
		unless authtag == cookie_authtag
			self.log.error "Invalid SCS cookie: authtags don't match: %p vs. %p" %
				[ authtag, cookie_authtag ]
			return nil
		end

		# Then the age of the SCS cookie (as deduced by ATIME field value and
		# current time provided by the server clock) is decoded and compared to
		# the maximum time-to-live defined by the max_session_age parameter.
		session_age = Time.now - Time.at( atime.to_i )
		# self.log.debug "  session is %d seconds old" % [ session_age ]
		if session_age > self.max_session_age
			self.log.error "Session expired %d seconds ago." % [ session_age - self.max_session_age ]
			return nil
		end

		# In case the "age" check is passed, the DATA and IV fields are finally
		# decoded (step 8.), so that the original plain text data can be
		# extracted from the encrypted and optionally compressed blob (step
		# 9.).
		#
		# Note that steps 5. and 7. allow any altered packets or expired
		# sessions to be discarded, hence avoiding unnecessary state decryption
		# and decompression.
		value = self.decrypt( data, iv, keyset.key )
		value = self.decompress( data ) if self.compression
		# self.log.debug "  decrypted cookie value is: %p" % [ value ]

		return new( cookie.name, value, cookie.options )
	end


	### Make an SCS authtag from the specified data, atime, and iv,
	### plus the tid from the given +keyset+ and hashed with its hkey.
	def self::make_authtag( data, atime, iv, keyset )
		# self.log.debug "Making authtag for data: %p, atime: %d, iv: %p, keyset: %p" %
			# [ data, atime, iv, keyset ]

		# AUTHTAG := HMAC(e(DATA)||e(ATIME)||e(TID)||e(IV))
		hashdata = [ data, atime.to_i, keyset.tid, iv ].
			collect {|val| self.encode(val.to_s) }.
			join( self.framing_byte )

		return OpenSSL::HMAC.digest( self.digest_type, keyset.hkey, hashdata )
	end



	#################################################################
	###	I N S T A N C E   M E T H O D S
	#################################################################

	### Set up some additional values used for SCS.
	def initialize( name, value, options={} ) # :notnew:
		@atime       = Time.now
		@keyset      = self.class.current_keyset
		@iv          = OpenSSL::Random.random_bytes( self.class.block_size )

		super
	end


	######
	public
	######

	# The absolute timestamp of the last operation on the session data, as a Time object
	attr_accessor :atime

	# The keyset that will be used when creating this cookie's payload
	attr_accessor :keyset

	# The initialization vector used when encrypting the cookie's payload
	attr_accessor :iv


	### Return the cookie data as an encrypted string after (optionally) compressing
	### it.
	def encrypted_data
		# 3.  DATA := Enc(Comp(plain-text-cookie-value), IV)
		plain_data = self.value
		plain_data = self.class.compress( plain_data ) if self.class.compression

		return self.class.encrypt( plain_data, self.iv, self.keyset.key )
	end


	### Make the encrypted cookie value.
	def make_valuestring
		data    = self.encrypted_data
		authtag = self.class.make_authtag( data, self.atime, self.iv, self.keyset )

		# scs-cookie-value  = eDATA "|" eATIME "|" eTID "|" eIV "|" eAUTHTAG
		return [ data, self.atime.to_i, self.keyset.tid, self.iv, authtag ].
			collect {|val| self.class.encode(val.to_s) }.
			join( self.class.framing_byte )
	end

end # class Strelka::SCSCookie

