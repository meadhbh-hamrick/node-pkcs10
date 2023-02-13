// csr.js
//
// Copyright (c) 2023 Meadhbh S. Hamrick
// All Rights Reserved.
//
// Released under a 3 clause BSD License. See ../LICENSE or
// https://opensource.org/licenses/BSD-3-Clause for details.
//
// Generates a PKCS#10 Certificate Signature Request from
// node-native public and private keys.

( function () {
  const crypto = require( "crypto" );

  const oid_rsa_encryption = Buffer.from( [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x01, 0x05, 0x00
  ] );

  const oid_rsa_sha256_signature = Buffer.from( [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x0b, 0x05, 0x00
  ] );

  const cri_empty_attributes = Buffer.from( [ 0xA0, 0x00 ] );

  const name_components_to_oid = {
    // From RFC4519

    // User Id
    "uid": {
      "oid": [
        0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x01
      ],
      "tag": 0x0C // UTF8String
    },

    // Domain Component
    "dc": {
      "oid": [
        0x06, 0x0a, 0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19
      ],
      "tag": 0x16 // IA5String
    },

    // From Annex A, X.520

    // Common Name
    "cn": {
      "oid": [ 0x06, 0x03, 0x55, 0x04, 0x03 ],
      "tag": 0x0C
    },

    // Surname
    "sn": {
      "oid": [ 0x06, 0x03, 0x55, 0x04, 0x04 ],
      "tag": 0x0C
    },

    // Country
    "c": {
      "oid": [ 0x06, 0x03, 0x55, 0x04, 0x06 ],
      "tag": 0x13 // Printable String
    },

    // State or Province
    "st": {
      "oid": [ 0x06, 0x03, 0x55, 0x04, 0x08 ],
      "tag": 0x0C
    },

    // Locality (city, county, etc.)
    "l": {
      "oid": [ 0x06, 0x03, 0x55, 0x04, 0x07 ],
      "tag": 0x0C
    },

    // Organization Name
    "o": {
      "oid": [ 0x06, 0x03, 0x55, 0x04, 0x0A ],
      "tag": 0x0C
    },

    // Organizational Unit
    "ou": {
      "oid": [ 0x06, 0x03, 0x55, 0x04, 0x0B ],
      "tag": 0x0C
    },

    // Title (like Mrs., Miss, Dr., Mr., etc.)
    "title": {
      "oid": [ 0x06, 0x03, 0x55, 0x04, 0x0C ],
      "tag": 0x0C
    },

    "name": {
      "oid": [ 0x06, 0x03, 0x55, 0x04, 0x29 ],
      "tag": 0x0C
    },

    "gn": {
      "oid": [ 0x06, 0x03, 0x55, 0x04, 0x2A ],
      "tag": 0x0C
    },

    "initials": {
      "oid": [ 0x06, 0x03, 0x55, 0x04, 0x2B ],
      "tag": 0x0C
    },

    // From PKCS#9 / RFC2985

    "emailaddress": {
      "oid": [ 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01 ],
      "tag": 0x16
    }
  };

  // function entagify()
  //
  // Takes a tag (number) and contents (a buffer) and returns
  // a buffer with the tag octet, length octet(s) and contents.

  function entagify( tag, contents ) {
    let length = contents.length;
    let length_octets;

    if( length < 128 ) {
      length_octets = Buffer.from( [ length ] );
    } else if( length < 256 ) {
      length_octets = Buffer.from( [ 129, length ] );
    } else {
      length_octets = Buffer.from( [ 130, (length >> 8) & 0xFF, length & 0xFF ] );
    }

    let rv =
      Buffer.concat( [ Buffer.from( [ tag ] ), length_octets, contents ] );

    return rv;
  }

  // function dn_component()
  //
  // Takes a key (string) - something like L, ST, O, OU - which
  // represents a type of DN component and returns a buffer with
  // a DER Sequence in Set with OID and Value.

  function dn_component( key, value ) {

    const _key   = String( key ).toLowerCase();

    var oid_info = name_components_to_oid[ _key ];

    if( undefined === oid_info ) {
      return Buffer.from( [] );
    }

    const value_as_buffer = Buffer.from( String( value ) );

    const _sequence =
      entagify( 0x31, entagify( 0x30, Buffer.concat( [
        Buffer.from( oid_info.oid ), entagify( oid_info.tag, value_as_buffer )
      ] ) ) )
    ;

    return _sequence;
  }

  // function dn_string_to_sequence()
  //
  // Takes a string like "/C=US/O=Whomever/CN=example.com" and
  // converts it into a buffer containing the "subject" element
  // of a PKCS#10 request.

  function dn_string_to_sequence( input ) {

    const sn_array = input.split( "/" ).slice(1).reduce( ( a, c ) => {
      a.push( c.split( "=" ) );
      return a;
    }, [] );

    const sequence_interior = Buffer.concat(
      sn_array.reduce( ( a, c ) => {
        a.push( dn_component.apply( this, c ) );
        return a;
      }, [] )
    );

    const sequence = entagify( 0x30, sequence_interior );;

    return sequence;
  }

  // constructor CSR()
  //
  // Creates a CSR object; takes an object with elements:
  //   "subjectName" (string) - Subject Name, looks like "/C=US/O=Whatever"
  //   "publicKey" (object) - Public Key Object
  //   "privateKey" (object) - Private Key Object from crypto.genKeyPair()
  //
  // Here's a simple example:
  //
  //   let keyPair = crypto.generateKeyPairSync( "RSA", {
  //     modulusLength: 3144,
  //     publicExponent: 0x10001
  //   } );
  //
  //   let pkcs10_csr = new CSR( {
  //     publicKey: keyPair.publicKey,
  //     privateKey: keyPair.privateKey,
  //     subjectName: "/C=US/ST=Washington/L=Seattle/CN=www.example.com"
  //   } );
  //
  //   pkcs10_csr.generate();
  //
  //   let pkcs10_csr_pem = pkcs10_csr.toPem();

  function CSR( options ) {
    // Copy over items from the options object
    [ "privateKey", "publicKey", "subjectName" ].forEach( function( e ) {
      if( undefined !== options[ e ] ) {
        this[ e ] = options[ e ];
      }
    }.bind( this ) );
  }

  // function generate()
  //
  // Call this to generate the CSR from the parameters previously
  // set.  Call .toPEM() or .toDER() afterwards to extract a PEM
  // string or a Buffer containing the DER representation.

  CSR.prototype.generate = function () {
    if(
      ( undefined === this.privateKey ) ||
      ( undefined === this.subjectName )
    ) {
      throw new Error( "Can't generate CSR without subjectName and privateKey" );
    }

    let publicKeyJwk =
      this.publicKey.export( { type: "pkcs1", format: "jwk" } );

    let spk_modulus = Buffer.from( publicKeyJwk.n, "base64" );
    let spk_public_exponent = Buffer.from( publicKeyJwk.e, "base64" );

    const cri = entagify( 0x30, Buffer.concat( [
      Buffer.from( [ 0x02, 0x01, 0x00 ] ),             // version
      dn_string_to_sequence( this.subjectName ),       // subject
      entagify( 0x30, Buffer.concat( [                 // subjectPKInfo
        oid_rsa_encryption,                            //   algorithm
        entagify( 0x03, Buffer.concat( [               //   subjectPublicKey
          Buffer.from( [ 0x00 ] ),
          entagify( 0x30, Buffer.concat( [
            entagify( 0x02, spk_modulus ),             //     modulus (n)
            entagify( 0x02, spk_public_exponent )      //     public exponent (e)
          ] ) ) ] ) )
      ] ) ),
      cri_empty_attributes                             // attributes
    ] ) );

    const signature = crypto
      .createSign( "RSA-SHA256" )
      .update( cri )
      .sign( this[ "privateKey" ] )
    ;

    this.csr = entagify( 0x30, Buffer.concat( [
      cri,
      oid_rsa_sha256_signature,
      entagify( 0x03, Buffer.concat( [
        Buffer.from( [ 0x00 ] ),
        signature
      ] ) )
    ] ) );

    return this;
  };

  // function toPEM()
  //
  // Call this after calling .generate() to return a PEM encoded
  // version of the CSR.

  CSR.prototype.toPEM = function () {
    if( undefined === this.csr ) {
      throw new Error( "Must call generate() before toPEM()" );
    }

    const pem =
      "-----BEGIN CERTIFICATE REQUEST-----\n" +
      this.csr.toString("base64").match( /.{1,64}/g ).join( '\n' ) +
      "\n" +
      "-----END CERTIFICATE REQUEST-----\n"
    ;

    return pem;
  };

  // function toPEM()
  //
  // Call this after calling .generate() to return a Buffer containing
  // the DER version of the CSR.

  CSR.prototype.toBuffer = function() {
    return this.csr;
  };

  module.exports = CSR;

} ) ();
