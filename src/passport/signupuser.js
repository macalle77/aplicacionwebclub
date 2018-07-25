var LocalStrategy   = require('passport-local').Strategy;

var usermysql = require('../model/user');

var bCrypt = require('bcrypt-nodejs');

var nodemailer = require('nodemailer');

var generator = require('generate-password');

var transporter = nodemailer.createTransport({
        service: 'Gmail',
				tls: { rejectUnauthorized: false },
        auth: {
            user: 'macalleish@gmail.com',
            pass: 'Calle.2017'
        }
});

module.exports = function(passport){

 passport.use('signupuser', new LocalStrategy({
            usernameField: 'dni',
            passwordField: 'password',
            passReqToCallback : true // allows us to pass back the entire request to the callback
        },
        function(req, username, password, done) {
            console.log('Registro comenzado con perfil:'+req.user.perfil);
            findOrCreateUser = function(){
                          // creamos el usuario
                          // Tendremos en cuenta si el usuario que está registrando tiene perfil Administrador.
                          // El nuevo usuario tendrá un password asignado por el administrador y el perfil indicado
                          var passwordnew=null

                          if(req.user.perfil=='administrador'){
                            passwordAsignada=createHash(password)
                            perfilAsignado=req.param('perfil')
                            passwordnew=req.param('password')
                          }
                          // O tiene pefil monitor, secretaria, en este caso el password se genera automáticamente.
                          // Y el perfil del nuevo usuario será siempre participante.
                          else{
                            passwordnew=generator.generate({
			                               length:7,
			                               numbers: true
                            })
                            console.log("PASSWORD PARTICIPANTE:"+passwordnew)
                            passwordAsignada=createHash(passwordnew);
                            perfilAsignado='participante';
                          }
                          var newUser = {
                            // set the user's local credentials
                            dni : username,
                            nombre : req.param('nombre'),
                            apellidos : req.param('apellidos'),
                            telefono: req.param('telefono'),
                            direccion: req.param('direccion'),
                            email: req.param('email'),
                            password : passwordAsignada,
                            perfil: perfilAsignado
                          };
                          //Salvar el nuevo usuaruio
                          usermysql.insertUser(newUser,function(err,rows){
                                  if (err){
                                      console.log('Error al salvar usuario: '+err);
                                      return done(null, false, req.flash('message','Asegurate que el nuevo usuario no esta ya registrado, con el mismo DNI, nombre y apellidos ó correo electrónico'));
                                  }
                                  console.log('Usuario registrado correctamente'+req.user.perfil);
                                  return done(null, req.user);
                          });
                          //envio de correo a usuario con password
                          textemail="Gracias por tu participación en las actividades del club.\n"+
				                            " Si este correo no va dirigido a tí, simplemente eliminalo.\n"+
				                            " En otro caso, has solicitado para poder acceder a la web deberás de utilizar:\n\n"+
				                            " Password:"+passwordnew+"\nSaludos Cordiales"

                          var mailOptions = {
                 		           from: 'macalleish@gmail.com',
                 		           to: req.param('email'),
                 		           subject: 'Solicitud de acceso a la web Club',
                 		           text: textemail
                          }

                          transporter.sendMail(mailOptions, function(error, info){
	                             if (error){
      		                          console.log(error)
       		                          callback(error,null)
	                             } else {
      		                         console.log("Email sent")
       		                         callback(null,info)
	                             }
                          });
                      //}
                }
            // Delay the execution of findOrCreateUser and execute the method
            // in the next tick of the event loop
            process.nextTick(findOrCreateUser);
        })

    );

    // Generates hash using bCrypt
    var createHash = function(password){
        return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
    }

}
