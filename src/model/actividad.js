//llamamos al paquete mysql que hemos instalado
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
var actModel = {};

//obtener actividad con identificador
actModel.getActividadId = function (id,callback)
{
	if (connection){
     sql="select * from Actividad where id_actividad="+id;
     connection.query(sql,function(error, result){
       if(error) callback(error,null)
       else	callback(null, result[0]);
     })
  }
}

//obtener listado de Actividades
actModel.getActividades = function (callback)
{
	if (connection){
     sql="select * from Actividad";
     connection.query(sql,function(error, result){
       if(error) throw error;
       else	callback(null, result);
     })
  }
}

//añadir actividad nueva
actModel.insertActividad = function(actData,callback)
{
	if (connection)
	{
    sql='INSERT INTO Actividad (titulo,descripcion,requisitos,fecha,inicio_inscripcion,fin_inscripcion) VALUES(' + connection.escape(actData.titulo)+','+
    connection.escape(actData.descripcion)+','+
    connection.escape(actData.requisitos)+','+
    connection.escape(actData.fecha)+','+
		connection.escape(actData.inicio)+','+
		connection.escape(actData.fin)+')'

    console.log("Insertar nueva actividad:"+sql);

		connection.query(sql,function(error, result)
		{
			if(error)
			{
				callback(error,null);
			}
			else
			{
        //devolvemos la última id insertada
        var lastAct=result.insertId;
        console.log('Ultimo id de actividad insertada:'+lastAct);

				/*	var monitor=actData.monitores;
					var valores;
					valores="("+lastAct+","+monitor[0]+")"
					if(monitor.length>1){
        		for(var i=1; i<monitor.length;i++){
							valores+=",("+lastAct+","+monitor[i]+")"
						}
					}

				sql='INSERT INTO Organizar (id_actividad,id_monitor) VALUES ' + valores

        console.log('Consulta de insercion en organizar:'+sql);
        connection.query(sql,function(error, result){
          if(error)
    			{
    				callback(error,null);
    			}
    			else
    			{
            callback(null,{"insertId" : result.insertId});
          }
        })*/
			}
		})
	}
}

//obtener actividad activa, estamos dentro del periodo de inscripcion
actModel.getActividad = function(callback){
  var fecha_actual=moment().format('YYYY-MM-DD');
  console.log('Fecha actual:'+fecha_actual);
  if (connection){
     sql="select * from Actividad where inicio_inscripcion<='"+
     fecha_actual +"' and fin_inscripcion>='"+ fecha_actual+"'";
     connection.query(sql,function(error, result){
       if(error || result.length==0){
				  console.log("Error no hay actividad activa")
			 		callback(error,null);
		 	 }
       else
       {
        	callback(null, result);
       }
     })
  }
}

//Actualizar actividad
actModel.updateActividad = function(dataAct,id,callback){
	if(connection){
		sql="update Actividad set descripcion="+connection.escape(dataAct.descripcion)+","+
		" requisitos="+connection.escape(dataAct.requisitos)+","+
		" fecha="+connection.escape(dataAct.fecha)+","+
		" inicio_inscripcion="+connection.escape(dataAct.inicio)+","+
		" fin_inscripcion="+connection.escape(dataAct.fin)+
		" where id_actividad="+id
		console.log("Actualización de actividad:"+sql)
		connection.query(sql,function(error, result){
			if(error)
				callback(error,null);
			else
			{
			 callback(null, result);
			}
		})
	}
}

//obtener listado de actividades por fecha
actModel.getActividadesFecha = function(desde,hasta,callback){
  if (connection){
     sql="select * from Actividad where fecha>='"+
     desde +"' and fecha<='"+ hasta +"'";
     console.log("consultar fecha actividad concreta:"+sql)
     connection.query(sql,function(error, result){
       if(error) callback(error,null);
       else callback(null, result);
     });
  }
}

//obtener listado con información de los monitores participantes en la actividad activa
actModel.getMonitoresParticipantes = function(callback){
	if(connection){
		var fecha_actual=moment().format('YYYY-MM-DD');
		sql="select * from Actividad where inicio_inscripcion<='"+
		fecha_actual +"' and fin_inscripcion>='"+ fecha_actual+"'";
		connection.query(sql,function(error, actividad){
			if(error) callback(error,null);
			else
			{
				sql="select DISTINCT dni as dni,nombre,apellidos,telefono,email from Usuarios inner join Organizar on "+
				"Usuarios.dni=Organizar.id_monitor where id_actividad="+actividad[0].id_actividad
				console.log("******SQL MONITORES1:"+sql);
				connection.query(sql,function(error,result){
					if(error) callback(error,null);
					else{
						console.log("consulta1 ejecutada con exito");
						callback(null, result);
					}
				})
			}
		})
	}
}

//obtener listado con información de los monitores no participantes en la actividad activa
actModel.getMonitoresNoParticipantes = function(callback){
	if(connection){
		var fecha_actual=moment().format('YYYY-MM-DD');
		sql="select * from Actividad where inicio_inscripcion<='"+
		fecha_actual +"' and fin_inscripcion>='"+ fecha_actual+"'";
		connection.query(sql,function(error, actividad){
			if(error) callback(error,null);
			else
			{
				sql="SELECT DISTINCT dni as dni ,nombre,apellidos,telefono,email FROM Usuarios left join Organizar on Usuarios.dni=Organizar.id_monitor"+
				" where perfil='monitor' and dni not in (select id_monitor from Organizar where id_actividad="+actividad[0].id_actividad+")"
				console.log("******SQL MONITORES2:"+sql);
				connection.query(sql,function(error,result){
					if(error) callback(error,null);
					else{
						console.log("consulta2 ejecutada con exito");
						callback(null, result);
					}
				})
			}
		})
	}
}

actModel.organizarActividadMonitor =function(id_monitor,id_actividad,callback){
	if(connection){
		sql='INSERT INTO Organizar (id_actividad,id_monitor) VALUES ('+
		id_actividad+','+id_monitor+')';
		console.log('Consulta de insercion en organizar:'+sql);
		connection.query(sql,function(error, result){
			if(error)
			{
				callback(error,null);
			}
			else
			{
				callback(null,{"insertId" : result.insertId});
			}
		})
	}
}

actModel.finOrganizarActividadMonitor =function(id_monitor,id_actividad,callback){
	if(connection){
		sql='DELETE FROM Organizar where id_actividad='+id_actividad+ ' and id_monitor='+id_monitor;
		console.log('Consulta de borrado en organizar:'+sql);
		connection.query(sql,function(error, result){
			if(error)
			{
				callback(error,null);
			}
			else
			{
				callback(null,{"deleteId" : result.deleteId});
			}
		})
	}
}

module.exports = actModel;
