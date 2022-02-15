const Usuario = require('../models/usuario.model');
const bcrypt = require('bcrypt-nodejs');
const jwt = require('../services/jwt');

function Registrar(req, res) {
    var usuarioModel = new Usuario();
    var parametros = req.body;

    if (parametros.nombre && parametros.apellido && parametros.email && parametros.password) {
        usuarioModel.nombre = parametros.nombre;
        usuarioModel.apellido = parametros.apellido;
        usuarioModel.email = parametros.email;
        usuarioModel.rol = 'USUARIO';
        usuarioModel.imagen = null;

        // BUSCAR SI EXISTE UN CORREO IGUAL
        Usuario.find({ email: parametros.email }, (err, emailEncontrado) => {
            if (err) return res.status(500).send({ mensaje: 'Error en la peticion.' });

            // SI NO EXISTE, AGREGA
            if (emailEncontrado.length == 0) {

                bcrypt.hash(parametros.password, null, null, (err, passwordEncriptada) => {
                    usuarioModel.password = passwordEncriptada;

                    usuarioModel.save((err, usuarioGuardado) => {
                        if (err) return res.status(500).send({ mensaje: 'Error en la peticio, de agregar usuario.' });
                        if (!usuarioGuardado) return res.status(500).send({ mensaje: 'Error al almacenar el usuario' });

                        return res.status(200).send({ usuario: usuarioGuardado })
                    });
                })

            } else {
                return res.status(500).send({ mensaje: 'El correo ya existe, ingrese uno nuevo.' })
            }
        })
    }
}

function Login(req, res) {
    var parametros = req.body;
    // BUSCAR USUARIO POR EMAIL
    Usuario.findOne({ email: parametros.email }, (err, usuarioEncontrado) => {
        if (err) return res.status(500).send({ mensaje: 'Error en la peticion de Usuario por Email' });
        if (usuarioEncontrado) {                                                  // TRUE OR FALSE
            // COMPARO CONTRASENA SIN ENCRIPTAR CON LA CONTRASENA ENCRIPTADA
            bcrypt.compare(parametros.password, usuarioEncontrado.password, (err, verificacionPassword) => {
                // VERIFICO SI LAS CONTRASENAS COINCIDEN
                if (verificacionPassword) {

                    if (parametros.obtenerToken === 'true') {
                        return res.status(200).send({
                            token: jwt.crearToken(usuarioEncontrado)
                        })
                    } else {
                        usuarioEncontrado.password = undefined;
                        return res.status(200).send({ usuario: usuarioEncontrado });
                    }

                } else {
                    return res.status(500).send({ mensaje: 'Las contraseñas, no coinciden.' })
                }
            })
        } else {
            return res.status(500).send({ mensaje: 'El usuario no se ha podido identificar.' })
        }
    })
}

function EditarUsuario(req, res) {
    var idUser = req.params.idUsuario;
    var parametros = req.body;


    if (req.user.rol === 'ADMIN') {
        Usuario.findByIdAndUpdate(idUser, parametros, { new: true },
            (err, usuarioActualizado) => {
                if (err) return res.status(500).send({ mensaje: 'Error en la peticion' });
                if (!usuarioActualizado) return res.status(500)
                    .send({ mensaje: 'Error al editar el Usuario' });

                return res.status(200).send({ usuario: usuarioActualizado });
            })
    } else {

        if (idUser != req.user.sub) return res.status(500)
            .send({ mensaje: 'No posee los permisos para editar este Usuario' });

        Usuario.findByIdAndUpdate(req.user.sub, parametros, { new: true },
            (err, usuarioActualizado) => {
                if (err) return res.status(500).send({ mensaje: 'Error en la peticion' });
                if (!usuarioActualizado) return res.status(500)
                    .send({ mensaje: 'Error al editar el Usuario' });

                return res.status(200).send({ usuario: usuarioActualizado });
            })
    }

}

module.exports = {
    Registrar,
    Login
}