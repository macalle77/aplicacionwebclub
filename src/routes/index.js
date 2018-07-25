var express = require('express');

var moment=require('moment');

var sleep=require('system-sleep');

var modelact = require ('../model/actividad');

var modelpart = require ('../model/participantes');

var modeluser = require ('../model/user');

var pdf = require('pdfkit');

var blobStream = require('blob-stream');

var router=express.Router();

var isAuthenticated = function (req, res, next) {
  // if user is authenticated in the session, call the next() to call the next request handler
  // Passport adds this method to request object. A middleware is allowed to add properties to
  // request and response objects
  console.log("hola autenticación");
  if (req.isAuthenticated())
    return next();
  // if the user is not authenticated then redirect him to the login page
  res.redirect('/');
}

module.exports = function(passport){

    /*
    router.get('/saludo', function(req,res){
      res.render('saludo',{ message: req.flash('message') });
    });

    router.post('/prueba', function(req,res){
      res.render('welcome',{ message: req.flash('message') });
    });
    */

    /* GET login page. */

    router.get('/', function(req, res) {
      // Display the Login page with any flash message, if any
      modelact.getActividad(function(err,activity){
        if(activity!=null){
          moment.locale('es')
          var fecha=moment(activity[0].fecha).format('dddd DD-MM-YYYY')
            res.render('index', {
              fecha: fecha,
              actividad: activity[0],
              message: req.flash('message')
            });
        }else{
            res.render('index', {
              actividad:null,
              message: req.flash('message')
            });
        }
      })
    });

      /* Handle Login POST */
    router.post('/login', passport.authenticate('login', {
      successRedirect: '/home',
      failureRedirect: '/',
      failureFlash : true
    }));

    /* GET Registration Page */
    /*router.get('/signup', function(req, res){
      res.render('register',{message: req.flash('message')});
    });*/

    /* Handle Registration POST */
    router.post('/signupuser', passport.authenticate('signupuser', {
      successRedirect: '/home?seccion=listado',
      failureRedirect: '/home?seccion=nuevo',
      failureFlash : true
    }));

    /* Recuperar password*/
    router.get('/recordaruser',function(req,res){
      res.render('recuperaracceso.ejs', {message:req.flash('message')})
    })

    router.post('/recoverpassword',function(req,res){
      console.log('nuevo password para:'+req.query.email);
      let email=req.body.email;
      let mensaje=null;
        modeluser.getUserEmail(email,function(err,user){
          if(err){
            mensaje='No existe este email registrado'
            res.render('index',{message:mensaje})
          }
          else{
            mensaje='Nuevo password enviado'
            modeluser.updateUserPassword(email,function(err,user){
                res.render('index',{message:mensaje})
            })
          }
        })
    })

    /* Handle Home Page and the rest*/

    router.get('/home', isAuthenticated, (req, res) => {
      let seccion=req.query.seccion || 'listado'

      if(req.user.perfil=="administrador"){
        console.log("Seccion administrador:"+seccion)
        modeluser.getUsers(function(err,users){
          if(seccion=="nuevo"){
            res.render('adminnewuser',{
              title: 'Nuevo usuario',
              message: req.flash('message')
            });
          }
          else{
            res.render('adminlistuser',{
              title: 'Lista de usuarios',
              users:users,
              mensajeRegistroError: req.flash('mensajeRegistroError'),
              mensajeRegistro: req.flash('mensajeRegistro')
            });
          }
        });
      }
      else if (req.user.perfil=="secretaria") {
        console.log("Seccion secretaria:"+seccion)
          if(seccion=="nuevo"){
            res.render('secrenewuser',{
              title: 'Nuevo usuario',
              message: req.flash('message')
            });
          }
          else if(seccion=="listado_actual"){
            modelact.getActividad(function(err,activity){
              if(activity==null){
                req.flash('mensajeRegistroError','No hay ningúna actividad programada actualmente')
                res.render('secregestactividad',{
                  title: 'Gestionar Actividades',
                  mensajeRegistroError: req.flash('mensajeRegistroError')
                });
              }
              else{
                modelpart.obtenerEstadoParticipantes(activity[0].id_actividad,function(error,listado){
                  res.render('secrelistuser',{
                    title: 'Lista de usuarios',
                    accion: 'activos',
                    tipo_listado: 'listado_actual',
                    users: listado
                  });
                })
              }
            })
          }
          else if(seccion=="listado_pendientes"){
            modelact.getActividad(function(err,activity){
              if(activity==null){
                req.flash('mensajeRegistroError','No hay ningúna actividad programada actualmente')
                res.render('secregestactividad',{
                  title: 'Gestionar Actividades',
                  mensajeRegistroError: req.flash('mensajeRegistroError')
                });
              }
              else{
                modelpart.obtenerEstadoParticipantesPendientes(activity[0].id_actividad,function(error,listado){
                  res.render('secrelistuser',{
                    title: 'Lista de usuarios',
                    accion: 'pendientes',
                    tipo_listado: 'listado_pendientes',
                    users: listado
                  });
                })
              }
            })
          }
          else if(seccion=="listado"){
            modeluser.getUsers(function(error,listado){
              res.render('secrelistuser',{
                title: 'Lista de usuarios',
                tipo_listado: 'listado',
                accion: 'gestion',
                users: listado
              });
            })
          }
          else if(seccion=="listado_actividades"){
            modelact.getActividades(function(error,listado){
              res.render('listadoactividadessecre',{
                title: 'Lista de actividades',
                tipo_listado: 'listado_actividades',
                moment: moment,
                actividades: listado
              })
            })
          }
          else if(seccion=="listado_actividades_filtro_fecha"){
            console.log("desde:"+req.query.desde);
            modelact.getActividadesFecha(req.query.desde,req.query.hasta,function(error,listado){
              res.render('listadoactividadessecre',{
                title: 'Lista de actividades en el periodo',
                tipo_listado: 'listado_actividades',
                moment: moment,
                actividades: listado
              })
            })
          }
          else{
            console.log("Error actividad no EXISTE")
            req.flash('mensajeRegistroError','No hay ningúna actividad programada actualmente')
            res.render('secregestactividad',{
              title: 'Gestionar Actividades',
              mensajeRegistroError: req.flash('mensajeRegistroError')
            });
          }
      }
      else if (req.user.perfil=="monitor") {
        console.log("Seccion monitor:"+seccion)
        modelact.getActividad(function(err,activity){
          if(activity==null && seccion=='listado_actividades'){
            actividadActiva=0
            modelact.getActividades(function(error,listado){
              res.render('listadoactividadesmon',{
                title: 'Lista de actividades',
                tipo_listado: 'listado_actividades',
                moment: moment,
                actividades: listado,
                actividadActiva: actividadActiva
              })
            })
          }
          else if(activity==null && seccion!='listado_actividades'){
            actividadActiva=0
            req.flash('message','Actualmente no hay ninguna actividad programada')
            res.render('monnewactividad',{
              //monitores: usuarios,
              title: 'Nueva Actividad',
              message: req.flash('message')
            })
          }
          else{
              actividadActiva=1

              if(seccion=="nuevo"){
                res.render('monnewuser',{
                  title: 'Nuevo usuario',
                  message: req.flash('message'),
                  actividadActiva: actividadActiva
                });
              }
              else if(seccion=="listado_actual"){
                modelact.getActividad(function(err,activity){
                  modelpart.obtenerEstadoParticipantes(activity[0].id_actividad,function(error,listado_participantes){
                    res.render('monlistuser',{
                      title: 'Lista de participantes',
                      accion: 'activos',
                      tipo_listado: 'listado_actual',
                      users: listado_participantes,
                      actividadActiva: actividadActiva
                    });
                  })
                })
              }
              else if(seccion=="listado_pendientes"){
                modelact.getActividad(function(err,activity){
                  modelpart.obtenerEstadoParticipantesPendientes(activity[0].id_actividad,function(error,listado){
                    res.render('monlistuser',{
                      title: 'Lista de usuarios no apuntados',
                      accion: 'pendientes',
                      tipo_listado: 'listado_pendientes',
                      users: listado,
                      actividadActiva: actividadActiva
                    });
                  })
                })
              }
              else if(seccion=="gestionar"){
                modelact.getActividad(function(err,activity){
                  res.render('mongestactividad',{
                    title: 'Gestionar Actividades',
                    actividad:activity[0],
                    fecha_actividad: moment(activity[0].fecha).format('YYYY-MM-DD'),
                    inicio_inscripcion: moment(activity[0].inicio_inscripcion).format('YYYY-MM-DD'),
                    fin_inscripcion:moment(activity[0].fin_inscripcion).format('YYYY-MM-DD'),
                    message: req.flash('message'),
                    mensajeRegistroError: req.flash('mensajeRegistroError'),
                    actividadActiva: actividadActiva
                  });
                })
              }
              else if(seccion=="listado_actividades"){
                modelact.getActividades(function(error,listado){
                  res.render('listadoactividadesmon',{
                    title: 'Lista de actividades',
                    tipo_listado: 'listado_actividades',
                    moment: moment,
                    actividades: listado,
                    actividadActiva: actividadActiva
                  })
                })
              }
              else if(seccion=="listado_actividades_filtro_fecha"){
                console.log("desde:"+req.query.desde);
                modelact.getActividadesFecha(req.query.desde,req.query.hasta,function(error,listado){
                  res.render('listadoactividadesmon',{
                    title: 'Lista de actividades en el periodo',
                    tipo_listado: 'listado_actividades',
                    moment: moment,
                    actividades: listado,
                    actividadActiva: actividadActiva
                  })
                })
              }
              else if(seccion=="listado_monitores"){
                modelact.getMonitoresParticipantes(function(error,listado1){
                  modelact.getMonitoresNoParticipantes(function(error,listado2){
                    res.render('monlistmonitor',{
                      title: 'Lista de monitores organizadores',
                      organizadores: listado1,
                      noorganizadores: listado2,
                      mensajeRegistro: req.flash('mensajeRegistro'),
                      actividadActiva: actividadActiva
                    });
                  })
                })
              }
              else if(seccion=="nuevaactividad"){
                  //modeluser.getUserPerfil('monitor',function(err,usuarios){
                    res.render('monnewactividad',{
                      //monitores: usuarios,
                      title: 'Nueva Actividad',
                      message: req.flash('message')
                    })
                  //})
              }
              else{
                modelact.getActividad(function(err,activity){
                console.log("Actividad actual......."+actividadActiva)
                  res.render('mongestactividad',{
                    title: 'Gestionar Actividades',
                    actividad:activity[0],
                    fecha_actividad: moment(activity[0].fecha).format('YYYY-MM-DD'),
                    inicio_inscripcion: moment(activity[0].inicio_inscripcion).format('YYYY-MM-DD'),
                    fin_inscripcion:moment(activity[0].fin_inscripcion).format('YYYY-MM-DD'),
                    mensajeRegistroError: req.flash('mensajeRegistroError'),
                    actividadActiva: actividadActiva
                  });
                })
              }
            }
        })
      }
      //Seccion de participante
      else{
      if(seccion=="gestionar"){
          modeluser.getUserDni(req.user.dni,function(error,usuario){
            console.log("Seccion participante:"+usuario[0].dni)
            res.render('pardatospersonales',{
              title: 'Datos Personales',
              user:usuario[0],
              existe:0,
              //message: req.flash('message'),
              mensajeRegistroError: req.flash('mensajeRegistroError')
            })
          })
      } else {
          modelact.getActividad(function(error,actividad){
            if(actividad==null){
              res.render('parnewactividad',{
                title: 'Participación',
                titulo: 'no',
                existe: 0,
                mensajeRegistroError: req.flash('mensajeRegistroError'),
                mensajeRegistro: req.flash('mensajeRegistro')
              })
            }
            else{
              modelpart.obtenerEstadoParticipante(req.user.dni,actividad[0].id_actividad,function(err,result){
                var existe=1
                var firmado=0
                if(result!=null){
                  if(result[0].firmado==1){
                  console.log("ya has firmado")
                  firmado=1
                  }
                }
                else{
                  existe=0
                }
                if(seccion=="nuevaactividad"){
                   res.render('parnewactividad',{
                    title: 'Participación',
                    titulo:actividad[0].titulo,
                    existe:existe,
                    firmado:firmado,
                    mensajeRegistroError: req.flash('mensajeRegistroError'),
                    mensajeRegistro: req.flash('mensajeRegistro')
                    });
                 }
                 else{
                   fecha=moment(actividad[0].fecha).format('YYYY-MM-DD')
                    res.render('parveractividad',{
                       title: 'Datos Actividad',
                       existe:existe,
                       actividad:actividad[0],
                       fecha_actividad:fecha,
                       message: req.flash('message'),
                       mensajeRegistroError: req.flash('mensajeRegistroError'),
                       mensajeRegistro: req.flash('mensajeRegistro')
                     });
                 }
              })
          }
      })
    }
    }
  })

    router.get('/asignaractividad/:id',isAuthenticated,(req,res)=>{
      let id_participante=req.params.id;
      modelact.getActividad(function(err,activity){
        if(err) res.redirect('/home?seccion=listado_pendientes');
        else {
            modelpart.apuntarActividad(id_participante,activity[0].id_actividad,function(err,activity){
              res.redirect('/home?seccion=listado_pendientes');
            })
        }
      })
    })

    router.get('/darbajaactividad/:id',isAuthenticated,(req,res)=>{
      let id_participante=req.params.id;
      modelact.getActividad(function(err,activity){
        if(err) res.redirect('/home?seccion=listado_actual');
        else {
            modelpart.darBajaActividad(id_participante,activity[0].id_actividad,function(err,activity){
              res.redirect('/home?seccion=listado_actual');
            })
        }
      })
    })

    router.get('/confirmarasistenciaactividad/:id',isAuthenticated,(req,res)=>{
      let id_participante=req.params.id;
      modelact.getActividad(function(err,activity){
        if(err) throw err
        else{
            modelpart.confirmarAsistenciaActividad(id_participante,activity[0].id_actividad,function(err,result){
                if(err) throw err;
                else{
                  message: "Asistencia gestionada";
                }
            })
          res.redirect('/home?seccion=listado_actual');
        }
      })
    })

    router.get('/confirmarpago/:id',isAuthenticated,(req,res)=>{
      let id_participante=req.params.id;
      modelact.getActividad(function(err,activity){
        if(err) throw err
        else{
            modelpart.confirmarPagoActividad(id_participante,activity[0].id_actividad,function(err,result){
                if(err) throw err;
                else{
                  message: "Pago de usuario gestionado";
                }
            })
          res.redirect('/home?seccion=listado_actual');
        }
      })
    })

    router.get('/firmadouser/:id',isAuthenticated,(req,res)=>{
         let id_participante=req.params.id;
         modelact.getActividad(function(err,activity){
           if(err) throw err
           else{
               modelpart.firmarActividad(id_participante,activity[0].id_actividad,function(err,result){
                   if(err) throw err;
                   else{
                     message: "Firma de usuario gestionada";
                   }
               })
             if(req.user.perfil=="monitor") res.redirect('/home?seccion=listado');
             else res.redirect('/home?seccion=listado_actual');
           }
         })
    })

    router.post('/condicionesactividad',isAuthenticated,(req,res)=>{
      id_participante=req.user.dni
      modelact.getActividad(function(err,activity){
        if(activity==null){
            console.log("mensajeRegistroError No hay ninguna actividad programada en este momento")
            req.flash('mensajeRegistroError','No hay ninguna actividad programada en este momento')
        }
        else
        {
          if(req.body.aceptar=="aceptar"){
            modelpart.obtenerEstadoParticipante(id_participante,activity[0].id_actividad,function(err,result){
                if(result!=null){
                  if(result[0].firmado==1){
                    console.log("ya has firmado")
                    req.flash('mensajeRegistroError','Ya has firmado...')
                    res.redirect('/home?seccion=nuevaactividad')
                  }
                  else{
                      modelpart.firmarActividad(id_participante,activity[0].id_actividad,function(err,result){
                        if(result==null){
                          req.flash('mensajeRegistroError','No estas apuntado a la actividad')
                          res.redirect('/home?seccion=nuevaactividad')
                        }
                        else{
                          req.flash('mensajeRegistro','Usuario apuntado a la actividad, aceptando las condiciones')
                          res.redirect('/home?seccion=listado')
                        }
                      })
                  }
                }
                else{
                  req.flash('mensajeRegistroError','No estas apuntado a la actividad')
                  res.redirect('/home?seccion=nuevaactividad')
                }
            })
          }
          else
            modelpart.darBajaActividad(id_participante,activity[0].id_actividad,function(err,result){
              if(result==null){
                req.flash('mensajeRegistroError','No estas apuntado a la actividad')
                res.redirect('/home?seccion=nuevaactividad')
              }
              else{
                  req.flash('mensajeRegistro','Usuario dado de baja de la actividad, recuerda de pasar por secretaria.....')
                  res.redirect('/home?seccion=listado')
              }
          })
        }
      })
    })

    router.post('/nuevaactividad',isAuthenticated,(req,res)=>{
      modelact.insertActividad(req.body,function(err,rows){
          if(err) throw err;
          res.redirect('/home?seccion=listado');
      })
    })

    router.post('/modificaractividad',isAuthenticated,(req,res)=>{
      modelact.getActividad(function(error,activity){
        if(activity==null) {
          res.redirect('/home');
        }
        else{
          modelact.updateActividad(req.body,activity[0].id_actividad,function(error,rows){
            if(error){
                console.log('Error en la actualización de la actividad')
                req.flash('mensajeRegistroError','Problemas con la actualización de los datos de la actividad');
                res.redirect('/home?seccion=gestionar');
            }
            else{
              req.flash('mensajeRegistro','Actividad actualizada, elige los monitores');
              res.redirect('/home?seccion=listado_monitores');
            }
          })
        }
      })
    })

    router.get('/deleteuser/:id',isAuthenticated,(req, res)=>{
      let id=req.params.id;
      console.log("borrado");
      modeluser.deleteUser(id,function(err,rows){
        if(err) throw err;
        else{
          if(req.body.tipo_listado=="listado_pendientes")
              res.redirect('/home?seccion=listado_pendientes');
          else if(req.body.tipo_listado=="listado_actual")
              res.redirect('/home?seccion=listado_actual');
          else res.redirect('/home?seccion=listado');
        }
      })
    });

    router.post('/updatedatospersonales',isAuthenticated,(req,res)=> {
        console.log("Valor req:"+req.body.nombre+"***"+req.body.tipo_listado+"***"+req.body.dni);
        if(req.body.confpassword==req.body.nuevopassword){
          modeluser.updateUser(req.body,function(err,rows){
            if(err){
              console.log('Error en la actualización datos personales')
              req.flash('mensajeRegistroError','Problemas con los nuevos datos nombre y apellidos ó correo electrónico duplicados');
              res.redirect('/home?seccion=gestionar');
            }
            else {
              req.flash('mensajeRegistro','Usuario actualizado');
              res.redirect('/home?seccion=listado');
            }
          })
        }
        else if (req.body.confpassword!=req.body.nuevopassword){
            req.flash('mensajeRegistroError','Asegurate que el password está confirmado');
            res.redirect('/home?seccion=gestionar');
        }
    });

    router.post('/updateuser',isAuthenticated,(req,res)=> {
            console.log("Valor req:"+req.body.nombre+"***"+req.body.tipo_listado);
            modeluser.updateUser(req.body,function(err,rows){
              if(err){
                 console.log('Error en la actualización')
                 req.flash('mensajeRegistroError','Asegurate que los nuevos datos no se corresponden, con el mismo DNI, nombre y apellidos ó correo electrónico');
              }
              else {
                req.flash('mensajeRegistro','Usuario actualizado');
              }
              if(req.body.tipo_listado=="listado_pendientes")
                    res.redirect('/home?seccion=listado_pendientes');
              else if(req.body.tipo_listado=="listado_actual")
                    res.redirect('/home?seccion=listado_actual');
              else res.redirect('/home?seccion=listado');
            })
    });

    router.get('/organizaractividad/:id',isAuthenticated,(req,res)=>{
      let id=req.params.id;
      modelact.getActividad(function(err,activity){
        if(err) res.redirect('/home?seccion=listado_monitores');
        else
        {
          modelact.organizarActividadMonitor(id,activity[0].id_actividad,function(err,rows){
              res.redirect('/home?seccion=listado_monitores');
          })
        }
      })
    })

    router.get('/finorganizaractividad/:id',isAuthenticated,(req,res)=>{
      let id=req.params.id;
      modelact.getActividad(function(err,activity){
        if(err) throw err
        else
        {
          modelact.finOrganizarActividadMonitor(id,activity[0].id_actividad,function(err,rows){
            if(err) throw err;
            else{
              res.redirect('/home?seccion=listado_monitores');
            }
          })
        }
      })
    })

    router.post('/listadomonitores',isAuthenticated,(req,res)=> {
          res.redirect('/home?seccion=listado_monitores');
    })

    router.post('/filtrarfecha',isAuthenticated,(req,res)=> {
         res.redirect('/home?seccion=listado_actividades_filtro_fecha&desde='+req.body.desde+'&hasta='+req.body.hasta);
    })

    router.post('/listado_actividades',isAuthenticated,(req,res)=> {
         res.redirect('/home?seccion=listado_actividades');
    })

    router.post('/listadoparticipantes',isAuthenticated,(req,res)=> {

          var doc = new pdf
          var stream = doc.pipe(blobStream());

          // draw some text
          doc.text('Listado de participantes...', 100, 20)
          .fontSize(12)
          .moveDown()

          modelact.getActividad(function(error,actividad){
            modelpart.obtenerEstadoParticipantes(actividad[0].id_actividad,function(error,usuarios){
                    for(var i=0;i<usuarios.length;i++){
                    if(usuarios[i].asiste=='1'){
                        doc.text(usuarios[i].nombre+' '+usuarios[i].apellidos,{
                          width: 412,
                          align: 'justify',
                          columns: 1
                        })
                        .font('Times-Roman', 12)
                        .moveDown()
                      }
                    }
                    doc.end();
              })
          })

          res.statusCode = 200;
          res.setHeader('Content-type', 'application/pdf');
          res.setHeader('Access-Control-Allow-Origin', '*');

          // Header to force download
          res.setHeader('Content-disposition', 'attachment; filename=Untitled.pdf');

          res.contentType('application/pdf');
          doc.pipe(res)

          /*stream.on('finish', function() {
              url = stream.toBlobURL('application/pdf')
              window.open(url)
          });*/
    })

    router.get('/obtenerinforme/:id',isAuthenticated,(req,res)=> {
          var id=req.params.id
          var doc = new pdf
          var stream = doc.pipe(blobStream());

            modelact.getActividadId(id,function(error,actividad){
              // draw some text
              doc.text('Informe de la actividad...', 100, 20)
              .fontSize(20)
              .moveDown()

              // and some justified text wrapped into columns
              doc.text(actividad.titulo+" realizada el "+actividad.fecha,{
               width: 412,
               align: 'justify',
               indent: 30,
               columns: 1,
               height: 300
              })
              .font('Times-Roman', 12)
              .moveDown()

              doc.text('Descripción:')
              .fontSize(20)
              .moveDown()

              doc.text(actividad.descripcion,{
               width: 412,
               align: 'justify',
               indent: 30,
               columns: 1,
               height: 300
              })
              .font('Times-Roman', 12)
              .moveDown()

              doc.text('Requisitos:')
              .fontSize(20)
              .moveDown()

              doc.text(actividad.requisitos,{
               width: 412,
               align: 'justify',
               indent: 30,
               columns: 1,
               height: 300
              })
              .font('Times-Roman', 12)
              .moveDown()
            })

            modelpart.obtenerEstadoParticipantes(id,function(error,usuarios){
                doc.addPage()

                doc.text('Lista de participantes:', 100, 20)
                .fontSize(20)
                .moveDown()
                  for(var i=0;i<usuarios.length;i++){
                    if(usuarios[i].asiste=='1'){
                      doc.text(usuarios[i].nombre+' '+usuarios[i].apellidos,{
                       width: 412,
                       align: 'justify',
                       columns: 1,
                      })
                      .font('Times-Roman', 12)
                      .moveDown()
                    }
                  }
                  doc.end();
              })

              // fin y descarga del documento pdf


              res.statusCode = 200;
              res.setHeader('Content-type', 'application/pdf');
              res.setHeader('Access-Control-Allow-Origin', '*');

              // Header to force download
              res.setHeader('Content-disposition', 'attachment; filename=Untitled.pdf');

              res.contentType('application/pdf');
              doc.pipe(res)

              /*stream.on('finish', function() {
                  url = stream.toBlobURL('application/pdf')
                  window.open(url)
              });*/
    })
    /* Logout */
    router.get('/signout', function(req, res) {
      req.logout();
      res.redirect('/');
    });

    return router;
}



/*module.exports = router;*/
