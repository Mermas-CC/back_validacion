# Usa una imagen base de Node.js con la versión 22.9.0
FROM node:22.9.0

# Crea un directorio de trabajo
WORKDIR /app

# Copia los archivos del proyecto
COPY package*.json ./
COPY . .

# Instala las dependencias
RUN npm install

# Expone el puerto
EXPOSE 5000

# Comando para ejecutar la aplicación
CMD [ "node", "server.js" ]

