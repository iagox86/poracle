# Poracle - Padding Oracle Attack Tool

This is Poracle - a tool for demonstrating padding oracle attacks!

This is going to be a fairly brief tutorial simply on how to use this tool; if
you want to understand the mechanics behind a padding oracle attack, your best
bet is to check out [my blog post on the subject](https://blog.skullsecurity.org/2013/padding-oracle-attacks-in-depth) or my [detailed by-hand walkthrough](https://blog.skullsecurity.org/2013/a-padding-oracle-example).

With that out of the way, let's look at how to use this tool!

## What can we do, exactly?

The idea of a padding oracle is conceptually simple: if you have a server
(we'll call it an "oracle") that accepts data encrypted with a block cipher,
then attempts to decrypt it and exposes whether or not the padding was correct,
you have a padding oracle vulnerability!

Why this actually works is beyond the scope, but see the blog links above.

Once you have a padding oracle, you can do some cool stuff:

1. Decrypt any encrypted data you're given (for example, if the data is in a
cookie, you can decrypt the cookie!)

2. Encrypt any arbitrary data, such that it can be cleanly decrypted by the
server using their key (for example, if the data in the cookie is a file path).

Poracle requires the user to write a little bit of Ruby code, enough to make
a web request and verify the result. The `Demo.rb` script shows the most common
usage and can be trivially modified.

## Create a module

A module is simply a little bit of Ruby code. Your best bet is probably to look
at Demo.rb and change it as needed.

Let's look at Demo.rb in detail:

    require 'httparty'
    require './Poracle'

The requires are pretty boring; `httparty` is a handy little gem for making HTTP
requests (you may need to run `gem install httparty` to use it). `Poracle` is
the meat of the library that does all the heavy lifting.

    BLOCKSIZE = 16

It's important to get the right blocksize. You can usually find the blocksize by
looking at how long the encrypted data is for a variety of data. If the length
is always a multiple of 16, then it's probably got a 16-byte blocksize. If the
length is occasionally a multiple of 8, then it's probably got an 8-byte
blocksize.

If you don't know the blocksize, just try both 8 and 16 - one of them will
almost certainly work.

    poracle = Poracle.new(BLOCKSIZE, true) do |data|
      url = "http://localhost:20222/decrypt/#{data.unpack("H*").pop}"
      result = HTTParty.get(url)
    
      # Return
      result.parsed_response !~ /Fail/
    end

This is the most important part: create an instance of `Poracle`! The block
underneath is called with some block of data, which is just a string of bytes.

It's up to you, the user, to figure out what to do with the bytes. The most
common thing is to encode them as hex and put them into the URL as a field, and
that's exactly what the demo does - it appends the data, encoded to hex, to the
URL.

Then, it looks to see if the response contains the word 'Fail'. In
RemoteTestServer.rb, that's the response for badly encrypted data.

The last line, being the end of a block, is the return value for the block.
You need to return True if the data was successfully decrypted, or False if it
was not.

## Decryption

Now we start the decrypting stuff!

    data = HTTParty.get("http://localhost:20222/encrypt").parsed_response
    print "Trying to decrypt: %s" % data

These lines simply get the encrypted string. This will probably be hardcoded
most of the time, I get it by making a request here just to show how that can
potentially be done.

    result = poracle.decrypt([data].pack('H*'))

And finally (for the decryption portion), this tells poracle to go ahead and
decrypt the data. This will make all the requests and call the block you
defined above a whole bunch of times. `result` becomes the magic string!

`[data].pack('H*')` converts the data from a user-readable hex string to a
string of binary data.

## Encryption

I also include an example of how to use the encryption function, although it's
not all that exciting for this particular app:

    data = "The most merciful thing in the world, I think, is the inability of the human mind to correlate all its contents."
    print "Trying to encrypt: %s" % data
    result = poracle.encrypt(data)

Basically, we take a string that we want to encrypt, and call poracle.encrypt()
on it. Poracle will find an encrypted string that decrypts to what you're
looking for!

Two caveats on encryption:

First, this is way slower than decryption. With decryption, we know the result
is probably going to be human-readable characters so we optimize the order in
which we do the tests to prioritize those. With encryption, it's just a binary
output, so we don't know.

Second, and more importantly, unless you control the IV, which you don't in the
demo I include, the encrypted string will start with garbage. We can't properly
encrypt the first block unless we control the IV, which is a limitation of this
attack.

When I ran this test to write this, I got:

    -----------------------------
    Encrypted string
    -----------------------------
    aac69a9f8c712bb2f295e98b8ed565ece2d33d47a7d846aca4f7acb19a23de18ad0b7e7b1f10c4e05ed68e90dc27d65b1302a10efbc1a997d226183479946c417abcc1999fde2b148f71747d0f1be3ec26888781dd51c11c33239b3872597c5c9258279de8dcb8bb3cb3e00dfbe2a18570204e7051b04273b5a25088ec6522f941414141414141414141414141414141
    -----------------------------

Which decrypts to:

    => "\x1C\xB2i\xE9gOpC\xDCX\xE3\x9B-x8)The most merciful thing in the world, I think, is the inability of the human mind to correlate all its contents."
