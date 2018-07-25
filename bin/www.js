#!/usr/bin/env node
var debug = require('debug')('crud-express-mysql');
var app = require('../src/app');

app.set('port', process.env.PORT || 3000);

var server = app.listen(app.get('port'), function() {
  //debug('Express server listening on port ' + server.address().port);
  console.log('Express server escuchando en puerto ' + server.address().port);
});
