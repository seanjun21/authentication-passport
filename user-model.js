var mongoose = require( 'mongoose' );
var bcrypt = require( 'bcrypt' );

var UserSchema = new mongoose.Schema( {
  username: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  }
} );

UserSchema.methods.validatePassword = function( password, callback ) {
  bcrypt.compare( password, this.password, function( error, isValid ) {
    if ( error ) {
      callback( error );
      return;
    }
    callback( null, isValid );
  } );
};


var User = mongoose.model( 'User', UserSchema );

module.exports = User;
