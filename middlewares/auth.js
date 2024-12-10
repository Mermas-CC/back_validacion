const jwt = require('jsonwebtoken');

// Usa la misma clave que tienes en server.js
const secretKey = 'mermitas'; // Asegúrate de que sea la misma

const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1]; // Obtener el token desde el encabezado

  if (!token) {
    return res.status(403).json({ message: 'Acceso denegado. Token no proporcionado.' });
  }

  // Usar la misma clave en jwt.verify()
  jwt.verify(token, secretKey, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Token inválido o expirado.' });
    }
    req.user = user; // Si el token es válido, agregar el usuario al request
    next(); // Pasar al siguiente middleware o ruta
  });
};

module.exports = authenticateToken;