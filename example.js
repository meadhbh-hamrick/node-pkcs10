#!/usr/bin/env node

const crypto = require( "crypto" );
const fs     = require( "fs" );
const CSR    = require( "./lib/csr.js" );

let debug = false;
let help  = false;
let public_path = "example.pub.pem";
let private_path = "example.key.pem";
let request_path = "example.csr.pem";
let subject_name = "/C=US/ST=Washington/L=Seattle/O=Tall Pine Certificate Shop and Bait Store/CN=www.example.com";
let bits = 2048;
let next;

process.argv.slice(2).forEach( ( e ) => {

  switch( next ) {
  case "public":
    public_path = e;
    next = undefined;
    break;

  case "private":
    private_path = e;
    next = undefined;
    break;

  case "request":
    request_path = e;
    next = undefined;
    break;

  case "b":
  case "bits":
    bits = Number( e );
    next = undefined;
    break;

  case "s":
  case "subject":
    subject_name = e;
  }

  if( "--" == e.substr( 0, 2 ) ) {
    next = e.substr(2);
  } else if( "-" == e.substr( 0, 1 ) ) {
    next = e.substr(1);
  } else {
    next = undefined;
  }

  switch( next ) {
  case "h":
  case "help":
    help = true;
    next = undefined;
    break;

  case "d":
  case "debug":
    debug = true;
    next = undefined;
    break;
  }
} );

if( help ) {
  console.error( `
Usage:
  example.js [options]...
Where options include:
  -h --help           - Prints this message and exits
  -d --debug          - Turns on debugging mode
  -s --subject <name> - Sets Subject Name
  -b --bits <number>  - Sets key size
  --private <path>    - Where to store private key
  --public  <path>    - Where to store public key
  --request <path>    - Where to store PKCS10 CSR request
Subject name uses forward-slash separated name components
(similar to openssl req -subj). Ex: "/C=US/ST=Washington"
` );
  process.exit( 0 );
}

// First, generate a key pair

if( debug ) {
  console.error( `Options are:
    Subject Name: ${subject_name}
        Key Size: ${bits}
Private Key Path: ${private_path}
 Public Key Path: ${public_path}
    Request Path: ${request_path}
` );
}

let _key_pair = crypto.generateKeyPairSync( "rsa", {
  modulusLength: bits,
  publicExponent: 0x10001
} );

if( debug ) {
  console.error( "Generated Key Pair\n" );
}

let _private_key_string =
  _key_pair.privateKey.export( { type: "pkcs1", format: "pem" } );

let _public_key_string =
  _key_pair.publicKey.export( { type: "pkcs1", format: "pem" } );

if( debug ) {
  console.error( "Private Key:\n" + _private_key_string );
  console.error( "Public Key:\n" + _private_key_string );
}

let _request = new CSR( {
    "privateKey": _key_pair.privateKey,
    "publicKey": _key_pair.publicKey,
    "subjectName": subject_name
  } )
  .generate()
;

if( debug ) {
  console.error( "Generated Certificate Signature Request\n" );
}

let _pem =
  _request
    .toPEM()
;

if( debug ) {
  console.error( "Certificate Signing Request:\n" + _pem );
}

fs.writeFileSync( public_path, _public_key_string );
fs.writeFileSync( private_path, _private_key_string );
fs.writeFileSync( request_path, _pem );
