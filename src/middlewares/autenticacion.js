const jwt = require('jwt-simple');
const moment = require('moment');
const secret = 'clave_secreta_IN6BM1';

exports.Auth = function (req, res, next) {
    // SI NO TIENE NADA LA CABECERA DE AUTHORIZATION, NO SE PUEDE UTILIZAR
    if (!req.headers.authorization){
        return res.status(404).send({ mensaje: 'La peticion no tiene la cabecera de Autorizacion'});
    }

    var token = req.headers.authorization.replace(/['"]+/g, '');
    
    try {
        // PAYLOAD, SON LOS DATOS ALMACENADOS EN EL TOKEN. SE DESENCRIPTAN.
        var payload = jwt.decode(token, secret);
        if(payload.exp <= moment().unix()){
            return res.status(404).send({ mensaje: 'El token ha expirado' });
        }
    } catch (error) {
        return res.status(500).send({ mensaje: 'El token no es valido'});
    }
    // CREA UNA VARIABLE LLAMADA USER EN EL REQ, AL USAR EL MIDDLEWARE.
    req.user = payload;
    next();
}
