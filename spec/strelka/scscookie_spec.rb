#!/usr/bin/env rspec -cfd -b

BEGIN {
	require 'pathname'
	basedir = Pathname( __FILE__ ).dirname.parent.parent
	libdir = basedir + 'lib'

	strelkalibdir = basedir.parent + 'Strelka/lib'

	$LOAD_PATH.unshift( basedir.to_s ) unless $LOAD_PATH.include?( basedir.to_s )
	$LOAD_PATH.unshift( libdir.to_s ) unless $LOAD_PATH.include?( libdir.to_s )
	$LOAD_PATH.unshift( strelkalibdir ) unless $LOAD_PATH.include?( strelkalibdir )
}

require 'configurability/behavior'
require 'loggability/spechelpers'
require 'openssl'
require 'timecop'

require 'rspec'
require 'strelka/scscookie'

require 'spec/lib/helpers'


# These examples are from Appendix A.
#
# A.1.  No Compression
#
#    The following parameters:
#
#    o  Plain text cookie: "a state string"
#    o  AES-CBC-128 key: "123456789abcdef"
#    o  HMAC-SHA1 key: "12345678901234567890"
#    o  TID: "tid"
#    o  ATIME: 1347265955
#    o  IV:
#       \xb4\xbd\xe5\x24\xf7\xf6\x9d\x44\x85\x30\xde\x9d\xb5\x55\xc9\x4f
#
#    produce the following tokens:
#
#    o  DATA: DqfW4SFqcjBXqSTvF2qnRA
#    o  ATIME: MTM0NzI2NTk1NQ
#    o  TID: OHU7M1cqdDQt
#    o  IV: tL3lJPf2nUSFMN6dtVXJTw
#    o  AUTHTAG: AznYHKga9mLL8ioi3If_1iy2KSA
#
describe Strelka::SCSCookie do

	COOKIE_DATA     = 'a state string'
	AES_CBC_128_KEY = '123456789abcdef0'
	HMAC_SHA1_KEY   = '12345678901234567890'
	TID             = 'tid'
	ATIME           = 1347265955
	IV              = "\xb4\xbd\xe5\x24\xf7\xf6\x9d\x44\x85\x30\xde\x9d\xb5\x55\xc9\x4f"


	before( :all ) do
		setup_logging()
		described_class.configure
	end

	before( :each ) do
		described_class.current_keyset = nil
		described_class.last_keyset = nil
	end

	after( :all ) do
		reset_logging()
	end


	#
	# Shared Examples
	#

	it_behaves_like "an object with Configurability"


	#
	# Examples
	#

	context "configuration" do

		after( :each ) do
			# Restore defaults
			described_class.configure( nil )
		end

		it "can be configured to use a different cipher" do
			described_class.configure( cipher_type: 'aes-256-cfb' )
			described_class.cipher_type.should == 'aes-256-cfb'
		end

		it "resets its keysets if the configured cipher changes" do
			initial_keyset = described_class.current_keyset
			described_class.configure( cipher_type: 'aes-256-cfb' )
			described_class.current_keyset.should_not be( initial_keyset )
		end

		it "doesn't reset its keysets if the same cipher configuration is set again" do
			initial_keyset = described_class.current_keyset
			described_class.configure( cipher_type: described_class.cipher_type )
			described_class.current_keyset.should be( initial_keyset )
		end

		it "resets its keysets if the configured digest changes" do
			initial_keyset = described_class.current_keyset
			described_class.configure( digest_type: 'sha512' )
			described_class.current_keyset.should_not be( initial_keyset )
		end

		it "doesn't reset its keysets if the same digest configuration is set again" do
			initial_keyset = described_class.current_keyset
			described_class.configure( digest_type: described_class.digest_type )
			described_class.current_keyset.should be( initial_keyset )
		end

	end


	it "rotates its keysets when told to if the current keyset has expired" do
		initial_keyset = described_class.current_keyset
		Timecop.freeze( initial_keyset.expires + 1 ) do
			described_class.rotate_keys
			described_class.last_keyset.should be( initial_keyset )
			described_class.current_keyset.should_not be( initial_keyset )
		end
	end


	it "can be upgraded from a regular cookie" do
		header = described_class.new( 'auth', 'foom' ).to_s
		cookies = Strelka::Cookie.parse( header )

		scs_cookie = described_class.from_regular_cookie( cookies[:auth] )
		scs_cookie.should be_a( described_class )
		scs_cookie.value.should == 'foom'
	end


	it "can be upgraded from a regular cookie even after its keyset has expired" do
		initial_keyset = described_class.current_keyset

		Timecop.freeze( initial_keyset.expires - described_class.max_session_age / 3 ) do
			header = described_class.new( 'auth', 'foom' ).to_s

			Timecop.freeze( initial_keyset.expires + 1 ) do
				described_class.rotate_keys

				cookies = Strelka::Cookie.parse( header )
				scs_cookie = described_class.from_regular_cookie( cookies[:auth] )
				scs_cookie.should be_a( described_class )
				scs_cookie.value.should == 'foom'
			end
		end
	end

	it "doesn't upgrade a cookie that's missing one of its fields" do
		header = described_class.new( 'auth', 'foom' ).to_s
		header.sub!( /=.*?\|/, '=' )
		cookies = Strelka::Cookie.parse( header )

		described_class.from_regular_cookie( cookies[:auth] ).should be_nil()
	end

	it "doesn't upgrade a cookie whose keyset has been expired" do
		header = described_class.new( 'auth', 'foom' ).to_s
		cookies = Strelka::Cookie.parse( header )

		described_class.current_keyset = nil
		described_class.last_keyset = nil

		described_class.from_regular_cookie( cookies[:auth] ).should be_nil()
	end

	it "doesn't upgrade a cookie that has expired" do
		Timecop.freeze( Time.now ) do
			initial_keyset = described_class.current_keyset
			header = described_class.new( 'auth', 'foom' ).to_s

			Timecop.freeze( Time.now + described_class.max_session_age + 1 ) do
				described_class.rotate_keys

				cookies = Strelka::Cookie.parse( header )
				described_class.from_regular_cookie( cookies[:auth] ).should be_nil()
			end
		end
	end



	context "A.1. No Compression" do

		before( :all ) do
			@time = Time.at( ATIME )
			Timecop.freeze( @time )
		end

		after( :all ) do
			Timecop.return
		end

		let( :keyset ) do
			ks         = Strelka::SCSCookie::KeySet.new
			ks.tid     = TID
			ks.key     = AES_CBC_128_KEY
			ks.hkey    = HMAC_SHA1_KEY
			ks.expires = @time + 3600
			ks
		end

		let( :cookie ) do
			described_class.new( 'authcookie', 'a state string', iv: IV, keyset: keyset )
		end


		it "can encrypt its payload" do
			cookie.encrypted_data.should == "^\x86\enR\xFFj\x9Dw\xC9\xEF\xA2\xEA\xE4\x14."
		end

		it "stringifies as a valid SCS cookie" do
			cookie.to_s.should == 'authcookie=XoYbblL/ap13ye+i6uQULg==|' +
				'MTM0NzI2NTk1NQ==|dGlk|tL3lJPf2nUSFMN6dtVXJTw==|0xPSM7RD' +
				'VytACfRuqlkRKucxEOM='
		end

	end


end

