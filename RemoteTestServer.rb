##
# RemoteTestServer
# Created: December 10, 2012
# By: Ron Bowes
#
# A very simple application that is vulnerable to a padding oracle
# attack. A Sinatra app with two paths - /encrypt and /decrypt. /encrypt
# sends data encrypted with the current key, and /decrypt attempts to
# decrypt it but only reveals whether or not it was successful.
##

require 'base64'
require 'openssl'
require 'sinatra'

set :port, 20222

# Note: Don't actually generate keys like this!
@@key = (1..32).map{rand(255).chr}.join

get '/encrypt' do
  text = "SkullSpace is a hackerspace in Winnipeg, founded December 2010. SkullSpace is a place for hackers, builders, programmers, artists, and anybody interested in how stuff works to gather in a common place and help focus their knowledge and creativity."
  c = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
  c.encrypt
  c.key = @@key

  return (c.update(text) + c.final).unpack("H*")
end

get /\/decrypt\/([a-fA-F0-9]+)$/ do |data|
  begin
    data = [data].pack("H*")
    c = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
    c.decrypt
    c.key = @@key
    c.update(data)
    c.final

    return "Success"
  rescue
    return "Fail"
  end
end


