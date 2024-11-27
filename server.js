// Importar las dependencias necesarias
const express = require('express');
const authenticateToken = require('./middlewares/auth');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const session = require('express-session');

// Configuración de la conexión a PostgreSQL
const pool = new Pool({
    user: 'elmer', // Cambia esto por tu usuario
    host: 'localhost', // Cambia esto si tu host es diferente
    database: 'prueba-validacion', // Cambia esto por tu nombre de base de datos
    password: 'mermitas', // Cambia esto por tu contraseña
    port: 5432, // Cambia esto si usas un puerto diferente
});

// Crear una instancia de la aplicación Express
const app = express();
const PORT = process.env.PORT || 5000;

// Configurar middleware
app.use(cors());
app.use(bodyParser.json());


const secretKey = 'mermitas'; // Cambia esto por una clave más segura
// Middleware para verificar el token
const verificarToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Obtener el token del encabezado Authorization
  
    if (!token) {
      return res.status(403).json({ message: 'Token no proporcionado' });
    }
  
    // Verificar el token
    jwt.verify(token, 'tu_clave_secreta', (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Token no válido' });
      }
      req.user = decoded; // Guardar la información decodificada del token en la solicitud
      next();
    });
  };

// Función asíncrona para encriptar la contraseña con un IV aleatorio
const encryptPassword = async (password) => {
    return new Promise((resolve, reject) => {
        try {
            // Generar un IV aleatorio
            const iv = crypto.randomBytes(16); // 16 bytes para CBC
            const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey), iv);
            
            let encrypted = cipher.update(password, 'utf-8', 'hex');
            encrypted += cipher.final('hex');

            // Retornar el IV junto con el texto cifrado
            resolve(iv.toString('hex') + encrypted); // Concatenar IV y texto cifrado
        } catch (error) {
            reject(error);
        }
    });
};

// Función asíncrona para desencriptar la contraseña
const decryptPassword = async (encryptedPassword) => {
    return new Promise((resolve, reject) => {
        try {
            // Separar el IV del texto cifrado
            const iv = Buffer.from(encryptedPassword.slice(0, 32), 'hex'); // Los primeros 16 bytes son el IV
            const encryptedText = encryptedPassword.slice(32); // El resto es el texto cifrado

            const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey), iv);
            
            let decrypted = decipher.update(encryptedText, 'hex', 'utf-8');
            decrypted += decipher.final('utf-8');
            
            resolve(decrypted);
        } catch (error) {
            reject(error);
        }
    });
};

// Función para comparar la contraseña ingresada con la contraseña almacenada encriptada
const comparePasswords = async (inputPassword, storedEncryptedPassword) => {
    try {
        // Desencriptar la contraseña almacenada
        const decryptedPassword = await decryptPassword(storedEncryptedPassword);
        
        // Comparar la contraseña ingresada con la desencriptada
        if (inputPassword === decryptedPassword) {
            console.log('¡Contraseña correcta!');
            return true;
        } else {
            console.log('Contraseña incorrecta');
            return false;
        }
    } catch (error) {
        console.error('Error al comparar contraseñas:', error);
        return false;
    }
};

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ error: 'No autorizado, no permitido' });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido' });
        }
        req.user = decoded; // Establecer el usuario en la solicitud
        next();
    });
};



// Ruta para crear una nueva palabra
app.post('/palabras', async (req, res) => {
    const { palabra_es, palabra_aimara, comentario } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO palabras (palabra_es, palabra_aimara, comentario) VALUES ($1, $2, $3) RETURNING *',
            [palabra_es, palabra_aimara, comentario]
        );
        res.status(201).json(result.rows[0]); // Devuelve la palabra creada
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al insertar la palabra');
    }
});


// Ruta para registrar un nuevo usuario
app.post('/register', async (req, res) => {
    const { username, password, rol } = req.body;

    // Verificar si el usuario ya existe
    const existingUser = await pool.query('SELECT * FROM nuevos_usuarios WHERE username = $1', [username]);
    if (existingUser.rows.length > 0) {
        return res.status(400).json({ message: 'Usuario ya existe' });
    }

    // Hashear la contraseña

    //borrar-luego-const passwordHash = await encryptPassword(password);

    const passwordHash = await bcrypt.hash(password, 10);

    try {
        const newUser = await pool.query(
            'INSERT INTO usuarios (username, password, rol) VALUES ($1, $2, $3) RETURNING *',
            [username, passwordHash, rol]
        );
        res.status(201).json(newUser.rows[0]); // Devuelve el nuevo usuario creado
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al registrar el usuario');
    }
});

// Ruta para obtener todas las palabras con detalles de validación
app.get('/palabras', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT p.id, p.palabra_es, p.palabra_aimara, p.comentario, p.validada, 
                   vp.fecha AS fecha_validacion, vp.es_correcta, u.nombre AS validador
            FROM palabras p
            LEFT JOIN versiones_palabras vp ON p.id = vp.palabra_id
            LEFT JOIN usuarios u ON vp.usuario_id = u.id
            ORDER BY p.id
        `);
        res.json(result.rows);  // Devuelve las palabras junto con la validación
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al obtener palabras con detalles de validación');
    }
});
app.get('/api/palabras', async (req, res) => {
    try {
      const result = await pool.query('SELECT * FROM nuevas_palabras');
      res.json(result.rows); // Enviar las palabras al frontend
    } catch (err) {
      console.error(err.message);
      res.status(500).send('Error al recuperar las palabras');
    }
  });
  

// Suponiendo que ya tienes tu servidor Express configurado
app.get('/versiones-palabras', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM versiones_palabras'); // Ajusta esto según tu conexión a la base de datos
        res.json(result.rows); // Asegúrate de que estás devolviendo los datos correctamente
    } catch (error) {
        console.error('Error al obtener versiones de palabras:', error);
        res.status(500).json({ error: 'Error al obtener versiones de palabras' });
    }
});
app.get('/validaciones/count', async (req, res) => {
    try {
      // Verifica si hay un usuario autenticado y el token es válido
      const userId = req.user.id; // Suponiendo que tienes el ID del usuario en el token
  
      const result = await pool.query(
        'SELECT COUNT(*) AS count FROM validaciones_usuarios WHERE usuario_id = $1 AND validada = TRUE',
        [userId]
      );
  
      // Devolver la respuesta
      res.json({ count: result.rows[0].count });
    } catch (error) {
      console.error('Error al obtener el contador de validaciones:', error);
      res.status(500).json({ error: 'Error al obtener el contador' });
    }
  });


// Suponiendo que ya tienes el middleware de autenticación implementado
// Ruta para obtener las palabras para la validación
// Ruta para obtener las palabras disponibles para validación
app.get('/palabras/no-validadas', authenticateToken, async (req, res) => {
    try {
        const usuarioId = req.user.id; // Obtenido del token JWT
        const resultado = await pool.query(
            `
            SELECT * 
            FROM palabras 
            WHERE validada IS NOT TRUE 
              AND contador < 4 
              AND id NOT IN (
                SELECT palabra_id 
                FROM validaciones_usuarios 
                WHERE usuario_id = $1
              )
            ORDER BY id ASC  -- Ordena por id para asegurar el orden original
            `,
            [usuarioId]
        );

        if (resultado.rows.length === 0) {
            return res.status(404).json({ message: 'No hay palabras disponibles para validar.' });
        }

        res.status(200).json(resultado.rows);
    } catch (error) {
        console.error('Error al obtener las palabras:', error);
        res.status(500).json({ message: 'Error al obtener las palabras.' });
    }
});





  




// Ruta para validar una palabra
app.post('/validar-palabra', async (req, res) => {
    const { palabra_id, usuario_id, comentario, es_correcta } = req.body;
  
    try {
      // Comprobamos si el usuario ya validó esta palabra
      const validacionExistente = await pool.query(
        'SELECT * FROM validaciones_usuarios WHERE palabra_id = $1 AND usuario_id = $2',
        [palabra_id, usuario_id]
      );
  
      if (validacionExistente.rows.length > 0) {
        return res.status(400).json({ message: 'Ya has validado esta palabra.' });
      }
  
      // Obtener la palabra y su contador
      const palabra = await pool.query('SELECT * FROM palabras WHERE id = $1', [palabra_id]);
      if (palabra.rows.length === 0) {
        return res.status(404).json({ message: 'Palabra no encontrada' });
      }
  
      const palabraData = palabra.rows[0];
      const nuevoContador = palabraData.contador + 1;  // Incrementar el contador
  
      // Actualizar la palabra con el nuevo contador
      await pool.query('UPDATE palabras SET contador = $1 WHERE id = $2', [nuevoContador, palabra_id]);
  
      // Insertar una nueva validación en la tabla 'validaciones_usuarios'
      await pool.query(
        'INSERT INTO validaciones_usuarios (palabra_id, usuario_id, comentario, es_correcta) VALUES ($1, $2, $3, $4)',
        [palabra_id, usuario_id, comentario, es_correcta]
      );
  
      // Actualizar el estado de la validación en la tabla de palabras
      await pool.query(
        'UPDATE palabras SET validada = true WHERE id = $1 AND contador >= 3', [palabra_id]
      );
  
      res.status(200).json({ message: 'Palabra validada correctamente' });
    } catch (error) {
      console.error('Error al validar la palabra', error);
      res.status(500).json({ message: 'Error al validar la palabra' });
    }
  });

// Ruta para obtener las versiones de las palabras
app.get('/palabras/versiones', async (req, res) => {
    try {
        const query = `
            SELECT 
    p.palabra_es AS palabra_original,
    v.id AS numero_version,
    p.palabra_aimara AS traduccion_aym,
    v.comentario, -- Obtener comentario de la tabla validaciones_usuarios
    CASE 
        WHEN v.es_correcta IS TRUE THEN 'Correcto'
        WHEN v.es_correcta IS FALSE THEN 'Incorrecto'
        ELSE 'Pendiente'
    END AS estado_validacion,
    v.usuario_id AS validador_id,
    v.fecha AS fecha_validacion
FROM 
    palabras p
LEFT JOIN 
    validaciones_usuarios v
ON 
    p.id = v.palabra_id
ORDER BY 
    p.id, v.fecha DESC;

        `;
        const result = await pool.query(query);
        res.json(result.rows);
    } catch (error) {
        console.error('Error al obtener las versiones de palabras:', error);
        res.status(500).send('Error al obtener las versiones de palabras');
    }
});





  
  




// Ruta para actualizar una palabra existente
app.put('/palabras/:id', async (req, res) => {
    const id = req.params.id;
    const { comentario } = req.body; // Solo recibimos comentario
    try {
        const selectResult = await pool.query('SELECT * FROM palabras WHERE id = $1', [id]);
        
        if (selectResult.rows.length === 0) {
            return res.status(404).send('Palabra no encontrada');
        }

        const result = await pool.query(
            'UPDATE palabras SET comentario = $1 WHERE id = $2 RETURNING *', 
            [comentario, id]
        );

        res.json(result.rows.length > 0 ? result.rows[0] : { message: 'Palabra no encontrada' });  // Devuelve la palabra actualizada
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al actualizar la palabra');
    }
});

// Ruta para eliminar una palabra
app.delete('/palabras/:id', async (req, res) => {
    const id = req.params.id;
    try {
        const result = await pool.query('DELETE FROM palabras WHERE id = $1 RETURNING *', [id]);
        res.json(result.rows.length > 0 ? result.rows[0] : { message: 'Palabra no encontrada' });  // Devuelve la palabra eliminada
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al eliminar la palabra');
    }
});
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Consulta a la base de datos
        const result = await pool.query(
            'SELECT id, nombre AS username, contraseña AS password, rol FROM Usuarios WHERE nombre = $1',
            [username]
        );

        const user = result.rows[0]; // Asumimos que `username` es único en la tabla Usuarios

        // Verifica si se encontró el usuario
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'Usuario no encontrado' 
            });
        }

        // Compara la contraseña ingresada con la almacenada en la base de datos
        const match = await bcrypt.compare(password, user.password);

        if (!match) {
            return res.status(401).json({ 
                success: false, 
                message: 'Contraseña incorrecta' 
            });
        }

        // Si la contraseña es correcta, genera un token JWT
        const token = jwt.sign(
            { id: user.id, username: user.username, rol: user.rol }, // Payload
            secretKey, // Clave secreta
            { expiresIn: '1h' } // Configuración de expiración del token
        );

        // Envía la respuesta con el token y los detalles del usuario
        res.status(200).json({ 
            success: true, 
            token, // Token JWT
            user: { 
                id: user.id,
                username: user.username,
                rol: user.rol 
            }
        });

    } catch (error) {
        console.error('Error al iniciar sesión:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error en el servidor' 
        });
    }
});







// Ruta para obtener usuarios con rol "valido"
app.get('/usuarios/valido', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE rol = $1', ['valido']);
        res.json(result.rows);  // Devuelve los usuarios con rol "valido"
    } catch (error) {
        console.error('Error al obtener usuarios:', error);
        res.status(500).send('Error al obtener usuarios');
    }
});

// Ruta para crear un nuevo usuario
app.post('/usuarios', async (req, res) => {
    const { nombre, contraseña, email, rol } = req.body;

    // Verificar si el usuario ya existe
    const existingUser = await pool.query('SELECT * FROM usuarios WHERE nombre = $1', [nombre]);
    if (existingUser.rows.length > 0) {
        return res.status(400).json({ message: 'Usuario ya existe' });
    }

    // Hashear la contraseña
    const passwordHash = await bcrypt.hash(contraseña, 10);

    try {
        const newUser = await pool.query(
            'INSERT INTO usuarios (nombre, contraseña, email, rol) VALUES ($1, $2, $3, $4) RETURNING *',
            [nombre, passwordHash, email, rol]
        );
        res.status(201).json(newUser.rows[0]); // Devuelve el nuevo usuario creado
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al registrar el usuario');
    }
});

// Ruta para actualizar un usuario existente
app.put('/usuarios/:id', async (req, res) => {
    const id = req.params.id;
    const { nombre, contraseña, email, rol } = req.body;

    try {
        const existingUser = await pool.query('SELECT * FROM usuarios WHERE id = $1', [id]);
        if (existingUser.rows.length === 0) {
            return res.status(404).send('Usuario no encontrado');
        }

        // Hashear la nueva contraseña si se proporciona
        const passwordHash = contraseña ? await bcrypt.hash(contraseña, 10) : existingUser.rows[0].contraseña;

        const result = await pool.query(
            'UPDATE usuarios SET nombre = $1, contraseña = $2, email = $3, rol = $4 WHERE id = $5 RETURNING *',
            [nombre, passwordHash, email, rol, id]
        );

        res.json(result.rows.length > 0 ? result.rows[0] : { message: 'Usuario no encontrado' });
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al actualizar el usuario');
    }
});

// Ruta para eliminar un usuario
app.delete('/usuarios/:id', async (req, res) => {
    const id = req.params.id;
    try {
        const result = await pool.query('DELETE FROM usuarios WHERE id = $1 RETURNING *', [id]);
        res.json(result.rows.length > 0 ? result.rows[0] : { message: 'Usuario no encontrado' });
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al eliminar el usuario');
    }
});


// Ruta para obtener todas las versiones de palabras
app.get('/versiones_palabras', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM versiones_palabras'); // Consulta a la tabla versiones_palabras
        res.json(result.rows); // Devuelve las filas como JSON
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Error en el servidor');
    }
});
app.post('/validar', async (req, res) => {
    const { palabraId, respuesta, comentario } = req.body;
    const userId = req.session.userId; // Obtén el ID del usuario desde la sesión
    
    // Verificar que los parámetros son válidos
    if (!palabraId || respuesta === undefined) {
      return res.status(400).send('Faltan datos necesarios.');
    }
  
    try {
      // Verifica si ya ha respondido esta palabra
      const existeRespuesta = await db.query(`
        SELECT 1 FROM respuestas_validadores WHERE usuario_id = $1 AND palabra_id = $2
      `, [userId, palabraId]);
  
      // Si existe respuesta, no permite validar de nuevo
      if (existeRespuesta.rowCount > 0) {
        return res.status(400).send('Ya has respondido esta palabra.');
      }
  
      // Si no existe respuesta, guarda la nueva respuesta
      await db.query(`
        INSERT INTO respuestas_validadores (usuario_id, palabra_id, respuesta, comentario)
        VALUES ($1, $2, $3, $4)
      `, [userId, palabraId, respuesta, comentario]);
  
      res.send('Respuesta registrada exitosamente');
    } catch (error) {
      console.error('Error al procesar la validación:', error);
      res.status(500).send('Ocurrió un error en el servidor.');
    }
  });
  

// Nueva ruta: Obtener todas las palabras con información de validación
app.get('/palabras-con-validacion', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT p.id, p.palabra_es, p.palabra_aimara, p.comentario, p.validada, 
                   vp.es_correcta, vp.comentario AS comentario_validacion, u.username AS validador
            FROM palabras p
            LEFT JOIN versiones_palabras vp ON p.id = vp.palabra_id
            LEFT JOIN nuevos_usuarios u ON vp.usuario_id = u.id
        `);
        res.json(result.rows); // Devuelve las palabras con detalles de validación
    } catch (error) {
        console.error(error);
        res.status(500).send('Error al obtener palabras con detalles de validación');
    }
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});


