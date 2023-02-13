const assert = require( "assert" );
const crypto = require( "crypto" );
const CSR    = require( "../lib/csr.js" );

let _key_pair = crypto.generateKeyPairSync( "rsa", {
  modulusLength: 2048,
  publicExponent: 0x10001
} );

let _threw = false;
let _request, _pem, _der, _error;

try {
  _request = new CSR( {
    "privateKey": _key_pair.privateKey,
    "publicKey": _key_pair.publicKey,
    "subjectName": "/C=US/ST=Washington/L=Seattle/O=Elsewhere, Inc./OU=Low Assurance Certification Authority/CN=www.example.com"
  } );
} catch( e ) {
  _threw = true;
  _error = e;
}

assert.ok( _threw == false, `Threw exception on constructor: ${_error?.stack}` );
assert.ok( "object" == typeof _request, `Request is something other than object: ${typeof _request}` );

try {
  _request.generate();
} catch( e ) {
  _threw = true;
  _error = e;
}

assert.ok( _threw == false, `Threw exception on generate(): ${_error?.stack}` );
assert.ok( "object" == typeof _request, `Request is something other than object: ${typeof _request}` );

try {
  _pem = _request.toPEM();
} catch( e ) {
  _threw = true;
  _error = e;
}

assert.ok( _threw == false, `Threw exception on toPEM(): ${_error?.stack}` );
assert.ok( "string" == typeof _pem, `_pem is something other than string: ${typeof _pem}` );

try {
  _der = _request.toBuffer();
} catch( e ) {
  _threw = true;
  _error = e;
}

assert.ok( _threw == false, `Threw exception on toBuffer(): ${_error?.stack}` );
assert.ok( Buffer.isBuffer( _der ), `_der is something other than buffer: ${typeof _der}` )

console.log(
  "   " +
    _der
    .toString( "hex" )
    .toUpperCase()
    .match( /.{1,2}/g )
    .join( " " )
    .match( /.{1,48}/g )
    .join( "\n   " )
);
