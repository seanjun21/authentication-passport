/* ---------- Dependencies ---------- */
var express = require( 'express' );
var bodyParser = require( 'body-parser' );
var mongoose = require( 'mongoose' );
var User = require( './user-model' );
var bcrypt = require( 'bcrypt' );
var passport = require( 'passport' );
var BasicStrategy = require( 'passport-http' ).BasicStrategy;

// Uses Express (factory) to create app object
var app = express();

// Uses JSON Parser to parse request 
var jsonParser = bodyParser.json();

// Setup basic strategy
var strategy = new BasicStrategy( function( username, password, callback ) {
  User.findOne( {
    username: username
  }, function( error, user ) {
    if ( error ) {
      callback( error );
      return;
    }

    if ( !user ) {
      return callback( null, false, {
        message: 'Incorrect username.'
      } );
    }

    user.validatePassword( password, function( error, isValid ) {
      if ( error ) {
        return callback( error );
      }

      if ( !isValid ) {
        return callback( null, false, {
          message: 'Incorrect password.'
        } );
      }
      return callback( null, user );
    } );
  } );
} );

// Use strategy with passport
passport.use( strategy );

/* ---------- User Endpoints ---------- */
app.post( '/users', jsonParser, function( request, response ) {

  // Body validation code
  if ( !request.body ) {
    return response.status( 400 ).json( {
      message: "No request body"
    } );
  }

  if ( !( 'username' in request.body ) ) {
    return response.status( 422 ).json( {
      message: 'Missing field: username'
    } );
  }

  var username = request.body.username;

  if ( typeof username !== 'string' ) {
    return response.status( 422 ).json( {
      message: 'Incorrect field type: username'
    } );
  }

  username = username.trim();

  if ( username === '' ) {
    return response.status( 422 ).json( {
      message: 'Incorrect field length: username'
    } );
  }

  if ( !( 'password' in request.body ) ) {
    return response.status( 422 ).json( {
      message: 'Missing field: password'
    } );
  }

  var password = request.body.password;

  if ( typeof password !== 'string' ) {
    return response.status( 422 ).json( {
      message: 'Incorrect field type: password'
    } );
  }

  password = password.trim();

  if ( password === '' ) {
    return response.status( 422 ).json( {
      message: 'Incorrect field length: password'
    } );
  }

  var user = new User( {
    username: username,
    password: password
  } );

  // Create a hash password for the User
  bcrypt.genSalt( 10, function( error, salt ) {
    if ( error ) {
      return response.status( 500 ).json( {
        message: 'Internal server error'
      } );
    }

    bcrypt.hash( password, salt, function( error, hash ) {
      if ( error ) {
        return response.status( 500 ).json( {
          message: 'Internal server error'
        } );
      }

      var user = new User( {
        username: username,
        password: hash
      } );

      user.save( function( error ) {
        if ( error ) {
          return response.status( 500 ).json( {
            message: 'Internal server error'
          } );
        }

        return response.status( 201 ).json( {} );
      } );
    } );
  } );
} );

app.use( passport.initialize() );

app.get( '/hidden', passport.authenticate( 'basic', { session: false } ), function( request, response ) {
  response.json( {
    message: 'Luke... I am your father'
  } );
} );

mongoose.connect( 'mongodb://localhost/auth' ).then( function() {
  app.listen( 8080 );
} );
