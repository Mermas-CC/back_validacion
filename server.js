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
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config(); 




// Crear una instancia de la aplicación Express
const app = express();
const PORT = process.env.PORT || 5000;



// Verificar si las variables de entorno están cargadas correctamente

console.log("Intentando conectar a PostgreSQL con:", {
    connectionString: process.env.DATABASE_URL || "NO DEFINIDO",
  });
  
  if (!process.env.DATABASE_URL) {
    console.error("❌ ERROR: La variable DATABASE_URL no está definida.");
    process.exit(1);
  }
  
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false } // ⚠️ Importante para Supabase
  });
  
  pool.connect()
    .then(() => console.log("✅ Conectado a Supabase"))
    .catch(err => console.error("❌ Error al conectar a Supabase:", err));
  
  module.exports = pool;

  
app.get('/test-db', async (req, res) => {
    try {
        const client = await pool.connect();
        const result = await client.query('SELECT NOW()');
        res.status(200).send(`Conexión exitosa a la base de datos: ${result.rows[0].now}`);
        client.release();
    } catch (error) {
        console.error('Error de conexión a la base de datos:', error);
        res.status(500).send('Error de conexión a la base de datos');
    }
});
// Configurar middleware
app.use(cors());
app.use(bodyParser.json());


const secretKey = 'mermitas'; // Cambia esto por una clave más segura
// Middleware para verificar el token


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
// Configuración de almacenamiento en disco
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');  // Directorio donde se guardan los archivos
    },
    filename: (req, file, cb) => {
        const ext = path.extname(file.originalname);
        cb(null, Date.now() + ext);  // Renombrar archivo para evitar conflictos
    }
});

const upload = multer({ storage: storage });

// Ruta para cargar el archivo de audio
app.post('/upload-audio', upload.single('audio'), (req, res) => {
    if (req.file) {
        const audioUrl = `/uploads/${req.file.filename}`;
        res.send({ message: 'Archivo subido exitosamente', filePath: audioUrl, audioUrl });
    } else {
        res.status(400).send('No se subió ningún archivo');
    }
});


// Ruta para generar y descargar el JSON
app.get('/descargar-json', async (req, res) => {
    try {
      const query = `
        SELECT 
          p.id AS palabra_id,
          p.palabra_es,
          json_agg(DISTINCT v.comentario) AS comentarios_agrupados
        FROM palabras p
        LEFT JOIN validaciones_usuarios v ON p.id = v.palabra_id
        GROUP BY p.id, p.palabra_es;
      `;
  
      const { rows } = await pool.query(query);
      const jsonFilePath = path.join(__dirname, 'corpus.json'); // Cambia el nombre aquí
  
      // Escribir el archivo JSON
      fs.writeFileSync(jsonFilePath, JSON.stringify(rows, null, 2), 'utf8');
  
      // Enviar el archivo al cliente con el nombre corpus.json
      res.download(jsonFilePath, 'corpus.json', (err) => {
        if (err) {
          console.error('Error al enviar el archivo:', err);
          res.status(500).send('Error al generar el archivo');
        }
      });
  
    } catch (error) {
      console.error('Error al ejecutar la consulta:', error);
      res.status(500).send('Error al obtener los datos');
    }
  });
  
// Servir archivos estáticos de la carpeta uploads
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Elimina o comenta la ruta innecesaria de audio si existe
// app.get('/audio/:filename', ...);

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
app.get('/validaciones/count', authenticateToken, async (req, res) => {
    try {
      const userId = req.user?.id; // Obtener el ID del usuario autenticado desde el token
  
      if (!userId) {
        return res.status(400).json({ error: 'ID de usuario no encontrado' });
      }
  
      const result = await pool.query(
        'SELECT COUNT(*) AS count FROM validaciones_usuarios WHERE usuario_id = $1',
        [userId]
      );
  
      res.json({ count: parseInt(result.rows[0].count, 10) }); // Asegurar que el resultado sea un número
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
            ORDER BY id ASC
            LIMIT 1
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
    const { palabra_id, usuario_id, comentario, es_correcta, pronunciacion_clip_url } = req.body;
  
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
        `INSERT INTO validaciones_usuarios (palabra_id, usuario_id, comentario, es_correcta, pronunciacion_clip_url) 
         VALUES ($1, $2, $3, $4, $5)`,
        [palabra_id, usuario_id, comentario, es_correcta, pronunciacion_clip_url || null]
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





  
  



app.put('/palabras/:id', async (req, res) => {
    const id = req.params.id;
    const { comentario } = req.body; // Solo recibimos comentario

    // Validación para asegurarse de que 'id' es un número entero
    if (isNaN(id)) {
        return res.status(400).send('ID debe ser un número entero');
    }

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
  


// ===== [Dashboard API] =====
app.get('/api/admin/dashboard', authenticateToken, async (req, res) => {
    try {
      // Realiza las consultas a la base de datos
      const [metrics, activity] = await Promise.all([
        pool.query(`
          SELECT 
            (SELECT COUNT(*) FROM usuarios) as total_usuarios,
            (SELECT COUNT(*) FROM palabras WHERE validada = false) as palabras_pendientes,
            (SELECT COUNT(*) FROM validaciones_usuarios) as total_interacciones
        `),
        
        pool.query(`
          SELECT 
  u.nombre as validador,
  p.palabra_es as termino,
  TO_CHAR(vu.fecha, 'DD/MM/YYYY HH24:MI') as fecha_formateada,
  vu.comentario,
  vu.pronunciacion_clip_url
FROM validaciones_usuarios vu
JOIN usuarios u ON vu.usuario_id = u.id
LEFT JOIN palabras p ON vu.palabra_id = p.id
ORDER BY vu.fecha DESC 
LIMIT 5

        `)
      ]);
  
      // Responde con los datos de métricas y actividad
      res.json({
        metricas: metrics.rows[0],
        actividad_reciente: activity.rows
      });
  
    } catch (error) {
      // En caso de error, responde con un mensaje adecuado
      console.error('Error en dashboard:', error);
      res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Ruta para obtener las últimas 5 validaciones del usuario autenticado
app.get('/api/validador/dashboard', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id; // Obtener el ID del usuario autenticado desde el token

        const result = await pool.query(`
            SELECT 
                p.palabra_es AS termino,
                TO_CHAR(vu.fecha, 'DD/MM/YYYY HH24:MI') AS fecha_formateada,
                vu.comentario,
                vu.pronunciacion_clip_url
            FROM validaciones_usuarios vu
            LEFT JOIN palabras p ON vu.palabra_id = p.id
            WHERE vu.usuario_id = $1
            ORDER BY vu.fecha DESC
            LIMIT 5
        `, [userId]);

        res.json({ actividad_reciente: result.rows });
    } catch (error) {
        console.error('Error al obtener el dashboard del validador:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ===== [Estadísticas para el dashboard de administrador] =====
app.get('/api/admin/stats', authenticateToken, async (req, res) => {
    try {
        // Validaciones por día (últimos 7 días)
        const validacionesPorDia = await pool.query(`
            SELECT 
                TO_CHAR(fecha, 'YYYY-MM-DD') AS dia,
                COUNT(*) AS total
            FROM validaciones_usuarios
            WHERE fecha >= NOW() - INTERVAL '7 days'
            GROUP BY dia
            ORDER BY dia ASC
        `);

        // Usuarios activos por día (últimos 7 días)
        const usuariosActivosPorDia = await pool.query(`
            SELECT 
                TO_CHAR(fecha, 'YYYY-MM-DD') AS dia,
                COUNT(DISTINCT usuario_id) AS total
            FROM validaciones_usuarios
            WHERE fecha >= NOW() - INTERVAL '7 days'
            GROUP BY dia
            ORDER BY dia ASC
        `);

        // Total validaciones (últimos 7 días)
        const totalValidaciones = await pool.query(`
            SELECT COUNT(*) AS total
            FROM validaciones_usuarios
            WHERE fecha >= NOW() - INTERVAL '7 days'
        `);

        // Total usuarios activos (últimos 7 días)
        const totalUsuariosActivos = await pool.query(`
            SELECT COUNT(DISTINCT usuario_id) AS total
            FROM validaciones_usuarios
            WHERE fecha >= NOW() - INTERVAL '7 days'
        `);

        res.json({
            validaciones_por_dia: validacionesPorDia.rows,
            usuarios_activos_por_dia: usuariosActivosPorDia.rows,
            total_validaciones: Number(totalValidaciones.rows[0]?.total || 0),
            total_usuarios_activos: Number(totalUsuariosActivos.rows[0]?.total || 0)
        });
    } catch (error) {
        console.error('Error en /api/admin/stats:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});
// ===== [Estadísticas para validador] =====
app.get('/api/validador/stats', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;

        // Total de validaciones del usuario
        const totalRes = await pool.query(
            `SELECT COUNT(*) AS total FROM validaciones_usuarios WHERE usuario_id = $1`,
            [userId]
        );
        const totalUsuario = parseInt(totalRes.rows[0].total, 10);

        // Total de validaciones de todos los usuarios y cantidad de usuarios
        const totalAllRes = await pool.query(
            `SELECT usuario_id, COUNT(*) AS total FROM validaciones_usuarios GROUP BY usuario_id`
        );
        const totalAll = totalAllRes.rows.reduce((sum, r) => sum + parseInt(r.total, 10), 0);
        const usuariosCount = totalAllRes.rows.length;
        const promedioTotal = usuariosCount > 0 ? Math.round(totalAll / usuariosCount) : 0;
        const maxUsuario = totalAllRes.rows.reduce((max, r) => Math.max(max, parseInt(r.total, 10)), 0);

        // Validaciones por día del usuario (últimos 7 días)
        const actividadRes = await pool.query(
            `SELECT 
                TO_CHAR(fecha, 'YYYY-MM-DD') AS dia,
                COUNT(*) AS cantidad
            FROM validaciones_usuarios
            WHERE usuario_id = $1 AND fecha >= NOW() - INTERVAL '7 days'
            GROUP BY dia
            ORDER BY dia ASC`,
            [userId]
        );

        // Promedio de validaciones por día de todos los usuarios (últimos 7 días)
        const actividadAllRes = await pool.query(
            `SELECT 
                TO_CHAR(fecha, 'YYYY-MM-DD') AS dia,
                COUNT(*) AS cantidad
            FROM validaciones_usuarios
            WHERE fecha >= NOW() - INTERVAL '7 days'
            GROUP BY dia
            ORDER BY dia ASC`
        );
        // Calcula promedio por día
        const actividadAllMap = {};
        actividadAllRes.rows.forEach(r => {
            actividadAllMap[r.dia] = parseInt(r.cantidad, 10);
        });
        const actividadUsuarioMap = {};
        actividadRes.rows.forEach(r => {
            actividadUsuarioMap[r.dia] = parseInt(r.cantidad, 10);
        });
        // Unifica días
        const dias = Array.from(new Set([
            ...actividadRes.rows.map(r => r.dia),
            ...actividadAllRes.rows.map(r => r.dia)
        ])).sort();

        const actividadPorDia = dias.map(dia => ({
            dia,
            usuario: actividadUsuarioMap[dia] || 0,
            promedio: usuariosCount > 0 ? Math.round((actividadAllMap[dia] || 0) / usuariosCount) : 0
        }));

        res.json({
            total_usuario: totalUsuario,
            promedio_total: promedioTotal,
            max_usuario: maxUsuario,
            actividad_por_dia: actividadPorDia // [{ dia, usuario, promedio }]
        });
    } catch (error) {
        console.error('Error en stats validador:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// Iniciar el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
