//llamamos al paquete mysql que hemos instalado
var mysql = require('mysql')
//creamos la conexion a nuestra base de datos con los datos de acceso de cada uno

var connection = mysql.createConnection({
    host     : '192.168.56.102',
    user     : 'miguel',
    password : 'miguel',
    database : 'prueba'
});

connection.connect(function(err) {
    if (err) throw err;
});

module.exports = connection;
