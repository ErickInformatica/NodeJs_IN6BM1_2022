// IMPORTACIONES
const express = require('express');
const ejemploController = require('../controllers/ejemplo.controller');

// MIDDLEWARES
const md_autenticacion = require('../middlewares/autenticacion');

// RUTAS
var api = express.Router();
// PRODUCTOS
api.get('/productos', ejemploController.ObtenerProductos);
api.get('/productos/:idProductos', ejemploController.ObtenerProductoId);
api.get('/buscarNombreProd/:nombreProducto', ejemploController.ObtenerProductoNombre);
api.post('/agregarProductos', ejemploController.AgregarProducto);
api.put('/editarProductos/:idProducto', ejemploController.EditarProducto);
api.delete('/eliminarProducto/:idProducto', ejemploController.EliminarProducto);

// EJEMPLOS
api.get('/kinal/:idKinal', ejemploController.EjemploParametroRuta);
api.get('/opcional/:idOpcional?', md_autenticacion.Auth ,ejemploController.EjemploParametroRutaOpcional);


module.exports = api;