// config/db.js
const mongoose = require('mongoose');
require('dotenv').config();

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('Conectado a la base de datos');
  } catch (error) {
    console.error('Error de conexión:', error);
    process.exit(1); // Salir del proceso si no se puede conectar
  }
};

module.exports = connectDB;
