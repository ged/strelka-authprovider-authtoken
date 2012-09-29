# -*- rspec -*-
# vim: set nosta noet ts=4 sw=4:

BEGIN {
	require 'pathname'
	basedir = Pathname.new( __FILE__ ).dirname.parent.parent.parent

	strelkalibdir = basedir.parent + 'Strelka/lib'

	$LOAD_PATH.unshift( basedir ) unless $LOAD_PATH.include?( basedir )
	$LOAD_PATH.unshift( strelkalibdir ) unless $LOAD_PATH.include?( strelkalibdir )
}

require 'rspec'

require 'spec/lib/helpers'

require 'configurability/behavior'

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
		@config = { :realm => 'Pern' }
	end

	after( :each ) do
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
	# Shared Examples
	#

	it_behaves_like "an object with Configurability"


	#
	# Examples
	#

	it "uses the app ID as the basic auth realm if none is explicitly configured" do
		described_class.realm.should == @app.conn.app_id
	end

	it "can be configured via the Configurability API" do
		described_class.configure( @config )
		described_class.realm.should == @config[:realm]
	end


	before( :all ) do
		described_class.configure( nil )
	end

	it "rejects a request with no scs cookie" do
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

	it "adds an SCSCookie to the request's response when authentication is established" do
		req = @request_factory.get( '/admin/console' )
		@provider.auth_succeeded( req, 'a_username' )

		cookie_name = described_class.cookie_name
		req.response.cookies[ cookie_name ].should be_a( Strelka::SCSCookie )
	end

end

