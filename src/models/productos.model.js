const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var ProductosSchema = Schema({
    nombre: String
});

module.exports = mongoose.model('Productos', ProductosSchema)