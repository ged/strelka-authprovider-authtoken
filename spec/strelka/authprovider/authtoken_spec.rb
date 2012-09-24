# -*- rspec -*-
# vim: set nosta noet ts=4 sw=4:

BEGIN {
	require 'pathname'
	basedir = Pathname.new( __FILE__ ).dirname.parent.parent.parent
	$LOAD_PATH.unshift( basedir ) unless $LOAD_PATH.include?( basedir )
}

require 'rspec'

require 'spec/lib/helpers'

require 'strelka'
require 'strelka/scscookie'
require 'strelka/authprovider/authtoken'


#####################################################################
###	C O N T E X T S
#####################################################################

describe Strelka::AuthProvider::AuthToken do

	before( :all ) do
		Strelka::SCSCookie.configure
		@cookie_name = described_class.cookie_name
		@request_factory = Mongrel2::RequestFactory.new( route: '/admin' )
		setup_logging()
	end

	before( :each ) do
		@app = stub( "Strelka::App", :conn => stub("Connection", :app_id => 'test-app') )
		@provider = Strelka::AuthProvider.create( :authtoken, @app )
		@config = {
			:realm => 'Pern',
			:users => {
				"lessa" => "8wiomemUvH/+CX8UJv3Yhu+X26k=",
				"f'lar" => "NSeXAe7J5TTtJUE9epdaE6ojSYk=",
			}
		}
	end

	after( :each ) do
		described_class.users = {}
		described_class.realm = nil
	end

	after( :all ) do
		reset_logging()
	end


	#
	# Helpers
	#

	# Make a valid basic authorization header field
	def make_auth_cookie( username )
		cookie_name = described_class.cookie_name
		return Strelka::SCSCookie.new( cookie_name, 'lessa', secure: true )
	end


	#
	# Examples
	#

	it "uses the app ID as the basic auth realm if none is explicitly configured" do
		described_class.realm.should == @app.conn.app_id
	end

	it "can be configured via the Configurability API" do
		described_class.configure( @config )
		described_class.realm.should == @config[:realm]
		described_class.users.should == @config[:users]
	end


	context "unconfigured" do

		before( :all ) do
			described_class.configure( nil )
		end

		it "rejects a request with no scs cookie and no credential parameters" do
			req = @request_factory.get( '/admin/console' )

			expect {
				@provider.authenticate( req )
			}.to finish_with( HTTP::UNAUTHORIZED, /requires authentication/i ).
			     and_header( www_authenticate: "AuthToken realm=test-app" )
		end

		it "rejects a request with an invalid SCS cookie" do
			req = @request_factory.get( '/admin/console' )
			req.cookies[ described_class.cookie_name ] = make_auth_cookie( 'lessa' )

			expect {
				@provider.authenticate( req )
			}.to finish_with( HTTP::UNAUTHORIZED, /requires authentication/i )
		end

		it "accepts a request with a valid SCS cookie" do
			auth_cookie = make_auth_cookie( 'lessa' )
			req = @request_factory.get( '/admin/console' )
			req.headers.cookie = auth_cookie.to_s

			@provider.authenticate( req ).should == 'lessa'
		end

	end


	context "configured with at least one user" do

		before( :all ) do
			described_class.configure( @config )
		end

		it "rejects a request with no scs cookie and no credential parameters" do
			req = @request_factory.get( '/admin/console' )

			expect {
				@provider.authenticate( req )
			}.to finish_with( HTTP::UNAUTHORIZED, /requires authentication/i ).
			     and_header( www_authenticate: "AuthToken realm=test-app" )
		end

		it "rejects a request with an invalid SCS cookie" do
			invalid_cookie = Strelka::Cookie.new( described_class.cookie_name, 'username' )
			req = @request_factory.get( '/admin/console' )
			req.cookies[ described_class.cookie_name ] = invalid_cookie

			expect {
				@provider.authenticate( req )
			}.to finish_with( HTTP::UNAUTHORIZED, /requires authentication/i )
		end

	end

end

