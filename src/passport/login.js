var LocalStrategy   = require('passport-local').Strategy;
var usermysql = require('../model/user');
var bCrypt = require('bcrypt-nodejs');

module.exports = function(passport){

  passport.use('login', new LocalStrategy({
            passReqToCallback : true
        },
        function(req, email, password, done) {
            // check in mongo if a user with email exists or not
            usermysql.getUserEmail(email,function(err,rows){
              if(err==null){
                if(rows.length > 0){
                  var user=rows[0];
                  if (!isValidPassword(user, password)){
                    console.log('Password no valido');
                    return done(null, false, req.flash('message', 'Password no valido.')); // redirect back to login page
                  }
                  // User and password both match, return user from done method
                  // which will be treated like success
                  return done(null, user);
                }
              }
              else{
                console.log('Usuario no encontrado con este email'+email);
                return done(null, false, req.flash('message', 'Usuario no encontrado.'));
              }
            });
        }
    ));

  var isValidPassword = function(user, password){
        return bCrypt.compareSync(password, user.password);
  }
}
