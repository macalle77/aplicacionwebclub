var moment = require('moment');

var connection=require('../libs/config-mysql')

//var mysql = require('mysql')
//creamos la conexion a nuestra base de datos con los datos de acceso de cada uno
/*connection = mysql.createConnection(
	{
		host : '192.168.56.102',
		user : 'miguel',
		password :'miguel',
		database : 'prueba'
	}
);*/

//creamos un objeto para ir almacenando todo lo que necesitemos
var partModel = {};


//Obtener información de participante en alguna actividades

partModel.obtenerEstadoParticipante = function(usuario,actividad,callback){
	if(connection){
	sql="select * from Participantes where id_actividad="+connection.escape(actividad)+
	" and id_usuario="+connection.escape(usuario)
		connection.query(sql,function(error,result){
			if(error || result.length==0){
				console.log("obtener estado participante no aceptado")
				callback(error,null)
			}
			else {
					console.log("obtener estado participante aceptado")
					callback(null,result);
			}
		})
	}
}

//Obtener un listado con información de los participantes que no están apuntados
partModel.obtenerEstadoParticipantesPendientes = function(actividad,callback){
	if(connection){
	sql="select * from listadoEstadosUsuarios where dni not in (select dni from listadoEstadosUsuarios where id_actividad="+connection.escape(actividad)+") group by dni"
	console.log("SQl"+sql);
		connection.query(sql,function(error,result){
			if(error) callback(error,null)
			else {
					callback(null,result);
			}
		})
	}
}

//Obtener un listado con información de los participantes de una actividad
partModel.obtenerEstadoParticipantes = function(actividad,callback){
	if(connection){
	sql="select * from listadoEstadosUsuarios where id_actividad="+connection.escape(actividad)+" order by asiste"
		connection.query(sql,function(error,result){
			if(error) callback(error,null)
			else {
					console.log("SQl"+sql);
					callback(null,result);
			}
		})
	}
}

//comprobar si usuario esta apuntado a una actividad ó no
/*partModel.comprobarEstadoActividad = function(partData,actData,callback){
	if(connection){
		sql='SELECT * from Participantes WHERE id_usuario='+connection.escape(partData)+
		' AND id_actividad='+connection.escape(actData)
		connection.query(sql,function(error,result){
			if(error) callback(error,null)
			else {
				if(result.length>0){
					console.log("SQl"+sql);
					callback(null,true);
				}
				else callback(null,false);
			}
		})
	}
}*/


/*partModel.comprobarEstadoActividad = function(partData,actData){
	if(connection){
		sql='SELECT * from Participantes WHERE id_usuario= '+connection.escape(partData)+
		'AND id_actividad='+connection.escape(actData)
		var valor=(function(){
			connection.query(sql,function(error,result){
				if(error) throw error
				else {
					if(result.length>0) return false;
					else return true;
				}
			})
		})()
		console.log("valor desde funcion:"+valor())
		return valor;
	}
}*/

//confirmar pago de usuario de la actividad actividad
partModel.firmarActividad = function(partData,actData,callback){
	if(connection){
		sql="SELECT firmado from Participantes where id_actividad=" +
		connection.escape(actData)+" AND id_usuario=" +	connection.escape(partData)
		console.log("Firmar actividad:"+sql)
		connection.query(sql,function(error, result){
			if(error || result.length==0 ) callback(error,null)
			else{
				console.log("Valor d firmado:"+result[0].firmado)
				if(result[0].firmado==1)
					sql1="UPDATE Participantes SET firmado=0 WHERE id_actividad="+
					connection.escape(actData)+" AND id_usuario=" +	connection.escape(partData)
				else{
					sql1="UPDATE Participantes SET firmado=1 WHERE id_actividad="+
					connection.escape(actData)+" AND id_usuario=" +	connection.escape(partData)
				}
				connection.query(sql1,function(error, result){
					if(error) throw error
					else {
						callback(null, {"updateId" : result});
					}
				})
			}
		})
	}
}

//confirmar asistencia de participante a la actividad
partModel.confirmarAsistenciaActividad = function(partData,actData,callback){
	if(connection){
		sql="SELECT asiste from Participantes where id_actividad=" +
		connection.escape(actData)+" AND id_usuario=" +	connection.escape(partData)
		connection.query(sql,function(error, result){
			if(error) throw error;
			else{
			console.log("Valor d pagado:"+result[0].aiste)
				if(result[0].asiste==1)
					sql1="UPDATE Participantes SET asiste=0 WHERE id_actividad="+
					connection.escape(actData)+" AND id_usuario=" +	connection.escape(partData)
				else{
					sql1="UPDATE Participantes SET asiste=1 WHERE id_actividad="+
					connection.escape(actData)+" AND id_usuario=" +	connection.escape(partData)
				}
				connection.query(sql1,function(error, result){
					if(error) throw error
					else {
						callback(null, {"updateId" : result});
					}
				})
			}
		})
	}
}

//confirmar pago de usuario de la actividad actividad
partModel.confirmarPagoActividad = function(partData,actData,callback){
	if(connection){
		sql="SELECT pagado from Participantes where id_actividad=" +
		connection.escape(actData)+" AND id_usuario=" +	connection.escape(partData)
		connection.query(sql,function(error, result){
			if(error) throw error;
			else{
			console.log("Valor d pagado:"+result[0].pagado)
				if(result[0].pagado==1)
					sql1="UPDATE Participantes SET pagado=0 WHERE id_actividad="+
					connection.escape(actData)+" AND id_usuario=" +	connection.escape(partData)
				else{
					sql1="UPDATE Participantes SET pagado=1 WHERE id_actividad="+
					connection.escape(actData)+" AND id_usuario=" +	connection.escape(partData)
				}
				connection.query(sql1,function(error, result){
					if(error) throw error
					else {
						callback(null, {"updateId" : result});
					}
				})
			}
		})
	}
}

//dar de baja usuario de una Actividad
partModel.darBajaActividad = function(partData,actData,callback){
	if(connection){
		sql="DELETE FROM Participantes WHERE id_actividad=" +
		connection.escape(actData)+" AND id_usuario=" +	connection.escape(partData)
		connection.query(sql,function(error, result){
			var resultado=result
			if(resultado.length>0){
				callback(null,{"borrarId" : result});
			}
			else{
				console.log("consulta borrar actividad:"+sql)
				error="no existe ese participante"
				callback(error,null)
			}
		})
	}
}

//asignar actividad a usuario desde secretaria
partModel.apuntarActividad = function(partData,actData,callback){
	if(connection){
		sql='INSERT INTO Participantes (id_actividad, id_usuario) VALUES (' +
		connection.escape(actData)+','+
		connection.escape(partData)+')'
		console.log("consulta apuntar a actividad:"+sql)
		connection.query(sql,function(error, result){
			if(error)	callback(error,null);
			else callback(null,{"insertId" : result});
		})
	}
}

module.exports = partModel;
