node-pkcs10

A Node.js package for generating PKCS#10 Certificate
Signing Requests using only the crypto module that comes
with node.  I was motivated to write this module when I
discovered it was difficult to find a node module with
similar functionality, but without external dependencies.

You should be able to install it using npm with the
command:

  npm install node-pkcs10

Then just import it into your JavaScript code with the
statement:

  const CSR = require( "node-pkcs10" );

You'll need to either read a public / private key pair
from somewhere or generate your own.  The following
snippet reads public and private keys from the
filesystem, generates a CSR and then writes it's PEM
representation to the filesystem:

  const fs = require( "fs" );

  const _public_key =
    crypto.createPublicKey(
      fs.readFileSync( "example.pub.pem" ) );

  const _private_key =
    crypto.createPrivateKey(
      fs.readFileSync( "example.key.pem" ) );

  const _csr = new CSR( {
    "subjectName": "/C=US/ST=Washington/L=Seattle/CN=example.com",
    "publicKey": _public_key,
    "privateKey": _private_key
  } )

  _csr.generate();

  fs.writeFileSync( "example.csr.pem", _csr.toPEM() );

The ./example.js file shows how to generate a key pair
using the crypto module.  Instead of reading keys from
the filesystem, it generates a key pair using the
crypto.generateKeyPair() function:

  let _key_pair = crypto.generateKeyPairSync( "rsa", {
    modulusLength: 2048,
    publicExponent: 0x10001
  } );

And then generates the CSR like this:

  let _request = new CSR( {
      "privateKey": _key_pair.privateKey,
      "publicKey": _key_pair.publicKey,
      "subjectName": subject_name
    } )
    .generate()
  ;

To test the module, try running ./example.js and then
asking openssl to generate a self-signed certificate
based on the private key and the CSR with this command:

  openssl x509 -req -days 365 -in example.csr.pem \
    -signkey example.key.pem -sha256 \
    -out example.crt.pem

and then

  openssl x509 -text -in example.crt.pem

No software project is ever complete.  A list of planned
improvements is in the ./todo.txt file.  Better testing,
attributes and ECC support.