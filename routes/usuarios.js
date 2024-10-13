// routes/usuarios.js
const express = require('express');
const Usuario = require('../models/Usuario');
const router = express.Router();

// Obtener usuarios por rol
router.get('/', async (req, res) => {
  const rol = req.query.rol;
  try {
    const usuarios = await Usuario.find({ rol });
    res.json({ usuarios });
  } catch (error) {
    console.error('Error al obtener usuarios:', error);
    res.status(500).json({ error: 'Error al obtener usuarios.' });
  }
});

// Crear un nuevo usuario
router.post('/', async (req, res) => {
  const { username, rol } = req.body;
  try {
    const nuevoUsuario = new Usuario({ username, rol });
    await nuevoUsuario.save();
    res.status(201).json(nuevoUsuario);
  } catch (error) {
    console.error('Error al crear usuario:', error);
    res.status(400).json({ error: 'Error al crear usuario.' });
  }
});

// Modificar un usuario
router.put('/:id', async (req, res) => {
  const { id } = req.params;
  const { username, rol } = req.body;
  try {
    const usuarioActualizado = await Usuario.findByIdAndUpdate(
      id,
      { username, rol },
      { new: true }
    );
    res.json(usuarioActualizado);
  } catch (error) {
    console.error('Error al actualizar usuario:', error);
    res.status(400).json({ error: 'Error al actualizar usuario.' });
  }
});

// Eliminar un usuario
router.delete('/:id', async (req, res) => {
  const { id } = req.params;
  try {
    await Usuario.findByIdAndDelete(id);
    res.status(204).send(); // No hay contenido
  } catch (error) {
    console.error('Error al eliminar usuario:', error);
    res.status(400).json({ error: 'Error al eliminar usuario.' });
  }
});

module.exports = router;
