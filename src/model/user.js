//llamamos al paquete mysql que hemos instalado
var bCrypt = require('bcrypt-nodejs');

//Generamos un password con las opciones que indiquemos
var generator = require('generate-password');

//Envio de correos electrónicos para gestionar accesos
var nodemailer = require('nodemailer');
// email sender function
// Definimos el transporter
var transporter = nodemailer.createTransport({
        service: 'Gmail',
				tls: { rejectUnauthorized: false },
        auth: {
            user: 'macalleish@gmail.com',
            pass: 'Calle.2017'
        }
});

var connection=require('../libs/config-mysql')

/*var mysql = require('mysql')
//creamos la conexion a nuestra base de datos con los datos de acceso de cada uno
connection = mysql.createConnection(
	{
		host : '192.168.56.102',
		user : 'miguel',
		password :'miguel',
		database : 'prueba'
	}
);*/



//var connection = require ('../libs/config-mysql');

//creamos un objeto para ir almacenando todo lo que necesitemos
var userModel = {};

//obtenemos todos los usuarios
userModel.getUsers = function(callback)
{
	if (connection)
	{
		connection.query('SELECT * FROM Usuarios ORDER BY nombre', function(error, rows) {
			if(error)
			{
				throw error;
			}
			else
			{
				callback(null, rows);
			}
		});
	}
}

//obtenemos lista de usuarios con un perfil determinado
userModel.getUserPerfil= function(perfil, callback)
{
	if (connection)
	{
		var sql = 'SELECT * FROM Usuarios WHERE perfil ='+connection.escape(perfil);
		connection.query(sql, function(error, rows)
		{
			if(error)
			{
				throw error;
			}
			else
			{
				callback(null, rows);
			}
		});
	}
}

//obtenemos lista de usuarios con un email determinado
userModel.getUserEmail= function(email, callback)
{
	if (connection)
	{
		var sql = 'SELECT * FROM Usuarios WHERE email ='+connection.escape(email);
		connection.query(sql, function(error, rows)
		{
			if(error)
			{
				call(error,null);
			}
			else
			{
				callback(null, rows);
			}
		});
	}
}

//obtenemos un usuario por su dni
userModel.getUserDni = function(dni,callback)
{
	if (connection)
	{
		var sql = 'SELECT * FROM Usuarios WHERE dni='+connection.escape(dni);
		connection.query(sql, function(error, rows)
		{
			if(error)
			{
				callback(error,null);
			}
			else
			{
			  console.log("SQL actualización:"+sql+"Resultado:"+rows.length+"nombre"+rows[0].nombre);
				callback(null, rows);
			}
		});
	}
}

//obtenemos un usuario por su nombre de usuario
userModel.getUserName = function(user,callback)
{
	if (connection)
	{
		var sql = 'SELECT * FROM accesos WHERE username = ' + connection.escape(user);
		connection.query(sql, function(error, row)
		{
			if(error)
			{
				callback(error, row);
			}
			else
			{
				callback(null, row);
			}
		});
	}
}

//obtenemos un usuario por su email
userModel.getUserEmail = function(email,callback)
{
	if (connection)
	{
		var sql = 'SELECT * FROM Usuarios WHERE email = ' + connection.escape(email);
		console.log("SQL EMAIL:"+sql)
		connection.query(sql, function(error, row)
		{
			if(error || row.length==0)
			{
				console.log("Mensaje error obtener usuario email");
				error='Usuario no existe con ese correo';
				callback(error, null);
			}
			else
			{
				console.log("Mensaje obtener usuario ok!");
				callback(null, row);
			}
		});
	}
}

//añadir un nuevo usuario
userModel.insertUser = function(userData,callback)
{
	if (connection)
	{
		connection.query('INSERT INTO Usuarios SET ?', userData, function(error, result)
		{
			if(error)
			{
				callback(error,null);
			}
			else
			{
				//devolvemos la última id insertada
				callback(null,{"insertId" : result.insertId});
			}
		});
	}
}

//actualizar un usuario
userModel.updateUser = function(userData, callback)
{
	//console.log(userData); return;
	if(connection)
	{
		var sql=null;
    console.log("Nuevo Password:"+userData.nuevopassword)
		if(userData.perfil==null) userData.perfil='participante';
		if(userData.nuevopassword=="" || userData.nuevopassword==null){
      if(userData.dninew==null){
			  sql = 'UPDATE Usuarios SET nombre = ' + connection.escape(userData.nombre) + ','
      }
      else{
        sql = 'UPDATE Usuarios SET dni= '+ connection.escape(userData.dninew) + ',' +
        'nombre = ' + connection.escape(userData.nombre) + ','
      }
      sql=sql+'apellidos = ' + connection.escape(userData.apellidos) + ','+
			'telefono = ' + connection.escape(userData.telefono) + ',' +
			'direccion = ' + connection.escape(userData.direccion) + ',' +
			'email = ' + connection.escape(userData.email) + ',' +
			'perfil = ' + connection.escape(userData.perfil) +
			' WHERE dni = ' + connection.escape(userData.dni);

			console.log('Consulta de actualización sin password:'+sql);
		}
		else{
			passwordactualizado= createHash(userData.nuevopassword)
			//sql = 'UPDATE Usuarios SET dni= '+ connection.escape(userData.dninew) + ',' +
      sql = 'UPDATE Usuarios SET nombre = ' + connection.escape(userData.nombre) + ',' +
			'apellidos = ' + connection.escape(userData.apellidos) + ','+
			'telefono = ' + connection.escape(userData.telefono) + ',' +
			'direccion = ' + connection.escape(userData.direccion) + ',' +
			'email = ' + connection.escape(userData.email) + ',' +
			'perfil = ' + connection.escape(userData.perfil) + ',' +
			'password =' + connection.escape(passwordactualizado)+
			' WHERE dni = ' + connection.escape(userData.dni);

			console.log('Consulta de actualización con password:'+sql);
		}
		connection.query(sql, function(error, result)
		{
			if(error)
			{
				callback(error, result);
			}
			else
			{
				callback(null,{"msg":"success"});
			}
		});
	}
}

//actualizar un usuario
userModel.updateUserPassword = function(email, callback)
{
	//console.log(userData); return;
	if(connection)
	{
		//var passwordnew='1234'
		var passwordnew=generator.generate({
			length:7,
			numbers: true
		})

		console.log("Password accesible:"+passwordnew)

		var sql = "UPDATE Usuarios SET password = '" + createHash(passwordnew) + "'"+
		" WHERE email = '" + email + "'";

		connection.query(sql, function(error, result)
		{

			if(error || result.affectedRows==0)
			{
				console.log('Consulta de actualización1:'+sql+'actualizado1:'+result.affectedRows);
				callback(error, null);
			}
			else
			{
				textemail="Gracias por tu participación en las actividades del club.\n"+
				" Si este correo no va dirigido a tí, simplemente eliminalo.\n"+
				" En otro caso, has solicitado para poder acceder a la web deberás de utilizar:\n\n"+
				" Password:"+passwordnew+"\nSaludos Cordiales"
				var mailOptions = {
       		from: 'macalleish@gmail.com',
       		to: email,
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

				console.log('Consulta de actualización2:'+sql+'actualizado2:'+result.affectedRows);
				callback(null,{"msg":"success"});
			}
		});
	}
}

//eliminar un usuario pasando la id a eliminar
userModel.deleteUser = function(id, callback)
{
	console.log("Valor de id:"+id)
	if(connection)
	{
		var sqlExists = 'SELECT * FROM Usuarios WHERE dni = ' + connection.escape(id);
		connection.query(sqlExists, function(err, row)
		{
			//si existe la id del usuario a eliminar
			if(row)
			{
				console.log("Borrar:"+connection.escape(id));
				var sql = 'DELETE FROM Usuarios WHERE dni = ' + connection.escape(id);
				connection.query(sql, function(error, result)
				{
					if(error)
					{
						throw error;
					}
					else
					{
						callback(null,{"msg":"deleted"});
					}
				});
			}
			else
			{
				console.log("No puede borrar:"+connection.escape(id));
				callback(null,{"msg":"notExist"});
			}
		});
	}
}

var createHash = function(password){
		return bCrypt.hashSync(password, bCrypt.genSaltSync(10), null);
}

//exportamos el objeto para tenerlo disponible en la zona de rutas
module.exports = userModel;
