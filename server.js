// Importar las dependencias necesarias
const express = require('express');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');

// Crear una instancia de la aplicación Express
const app = express();
const PORT = process.env.PORT || 5000;

// Configurar middleware
app.use(cors());
app.use(bodyParser.json());

const secretKey = 'mermitas'; // Cambia esto por una clave más segura

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ error: 'No autorizado' });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(403).json({ error: 'Token inválido' });
        }
        req.user = decoded; // Establecer el usuario en la solicitud
        next();
    });
};

// Configuración de la conexión a PostgreSQL
const pool = new Pool({
    user: 'elmer', // Cambia esto por tu usuario
    host: 'localhost', // Cambia esto si tu host es diferente
    database: 'prueba-validacion', // Cambia esto por tu nombre de base de datos
    password: 'mermitas', // Cambia esto por tu contraseña
    port: 5432, // Cambia esto si usas un puerto diferente
});

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

// Suponiendo que ya tienes el middleware de autenticación implementado
app.get('/palabras/no-validadas', verifyToken, async (req, res) => {
    const usuarioId = req.user.id; // Asegúrate de que esta línea funcione correctamente

    try {
        // Obtener todas las palabras
        const todasPalabras = await pool.query('SELECT * FROM palabras');

        // Obtener las palabras que el usuario ya ha validado
        const palabrasValidadas = await pool.query(
            'SELECT palabra_id FROM versiones_palabras WHERE usuario_id = $1',
            [usuarioId]
        );

        const idsPalabrasValidadas = palabrasValidadas.rows.map(row => row.palabra_id);

        // Filtrar las palabras no validadas
        const palabrasNoValidadas = todasPalabras.rows.filter(palabra => 
            !idsPalabrasValidadas.includes(palabra.id)
        );

        res.json(palabrasNoValidadas);
    } catch (error) {
        console.error('Error al obtener palabras no validadas:', error);
        res.status(500).json({ message: 'Error al obtener palabras no validadas' });
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

        const user = result.rows[0];

        // Verifica si se encontró el usuario
        if (user) {
            // Compara la contraseña
            const match = await bcrypt.compare(password, user.password);
            
            if (match) {
                // Si la contraseña es correcta, genera un token JWT
                const token = jwt.sign(
                    { id: user.id, username: user.username, rol: user.rol }, // Payload
                    'tu_clave_secreta', // Reemplaza esto con tu clave secreta real
                    { expiresIn: '1h' } // El token expirará en 1 hora
                );

                // Envía la respuesta con el token y el rol
                res.json({ 
                    success: true, 
                    token: token, // Incluye el token en la respuesta
                    user: { 
                        username: user.username, 
                        id: user.id,
                        rol: user.rol 
                    } 
                });
            } else {
                res.status(401).json({ success: false, message: 'Contraseña incorrecta' });
            }
        } else {
            res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }
    } catch (error) {
        console.error('Error al iniciar sesión:', error);
        res.status(500).json({ success: false, message: 'Error en el servidor' });
    }
});



// Endpoint para validar una palabra
app.post('/validar-palabra', async (req, res) => {
    const { palabra_id, usuario_id, comentario, es_correcta } = req.body;

    try {
        // Verificar si el validador ya ha validado la palabra
        const validacionesPrevias = await pool.query(
            'SELECT * FROM versiones_palabras WHERE palabra_id = $1 AND usuario_id = $2',
            [palabra_id, usuario_id]
        );

        if (validacionesPrevias.rows.length > 0) {
            return res.status(400).json({ message: 'Ya has validado esta palabra.' });
        }

        // Insertar nueva validación
        await pool.query(
            'INSERT INTO versiones_palabras (palabra_id, usuario_id, comentario, es_correcta) VALUES ($1, $2, $3, $4)',
            [palabra_id, usuario_id, comentario, es_correcta]
        );

        res.status(201).json({ message: 'Validación registrada exitosamente.' });
    } catch (error) {
        console.error('Error al validar la palabra:', error);
        res.status(500).json({ message: 'Error al validar la palabra.' });
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

