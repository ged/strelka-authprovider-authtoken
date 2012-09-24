#!/usr/bin/env rspec -cfd -b

BEGIN {
	require 'pathname'
	basedir = Pathname( __FILE__ ).dirname.parent.parent
	libdir = basedir + 'lib'

	$LOAD_PATH.unshift( basedir.to_s ) unless $LOAD_PATH.include?( basedir.to_s )
	$LOAD_PATH.unshift( libdir.to_s ) unless $LOAD_PATH.include?( libdir.to_s )
}

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
	end

	after( :all ) do
		reset_logging()
	end


	it "can be upgraded from a regular cookie" do
		cookie = Strelka::Cookie.new( 'token', 'a value' )
		scs_cookie = described_class.from_regular_cookie( cookie )
		scs_cookie.should be_a( described_class )
		scs_cookie.value.should == cookie.value
	end


	context "A.1. No Compression" do

		before( :all ) do
			@time = Time.at( ATIME )
			Timecop.freeze( @time )
		end

		let( :cookie ) do
			cookie = described_class.new( 'authcookie', 'a state string',
			                                key: AES_CBC_128_KEY,
                                           hkey: HMAC_SHA1_KEY,
                                            tid: TID,
                                          atime: ATIME )
			cookie.instance_variable_set( :@iv, IV )
			cookie
		end

		it "has an encoded data block that matches example from the spec" do
			cookie.encoded_data.should == "XoYbblL/ap13ye+i6uQULg=="
		end

		it "has an encoded atime block that matches example from the spec" do
			cookie.encoded_atime.should == 'MTM0NzI2NTk1NQ=='
		end

		it "has an encoded TID block that matches example from the spec" do
			cookie.encoded_tid.should == "dGlk"
		end

		it "has an encoded IV block that matches example from the spec" do
			cookie.encoded_iv.should == 'tL3lJPf2nUSFMN6dtVXJTw=='
		end

		it "has an encoded authtag block that matches example from the spec" do
			cookie.encoded_authtag.should == '0xPSM7RDVytACfRuqlkRKucxEOM='
		end

		it "stringifies as a valid cookie" do
			cookie.to_s.should == 'authcookie=XoYbblL/ap13ye+i6uQULg==|' +
				'MTM0NzI2NTk1NQ==|dGlk|tL3lJPf2nUSFMN6dtVXJTw==|0xPSM7RD' +
				'VytACfRuqlkRKucxEOM='
		end

	end


end

