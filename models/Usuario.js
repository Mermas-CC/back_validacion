// models/Usuario.js
const mongoose = require('mongoose');

const usuarioSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },
  rol: {
    type: String,
    required: true,
    enum: ['valido', 'invalido'], // Ajusta según tus necesidades
  },
  // Agrega otros campos según tus necesidades
});

const Usuario = mongoose.model('Usuario', usuarioSchema);

module.exports = Usuario;
