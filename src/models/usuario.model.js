const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var UsuarioSchema = Schema({
    nombre: String,
    apellido: String,
    email: String,
    password: String,
    rol: String,
    imagen: String
})

module.exports = mongoose.model('Usuarios', UsuarioSchema);