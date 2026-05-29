# Roles y Directrices de IA para el Repositorio de Base de Datos (PostgreSQL)

Este archivo define los estándares, roles y directrices que deben seguir los agentes de Inteligencia Artificial al trabajar en este proyecto. El objetivo es mantener una base de datos PostgreSQL robusta, moderna y documentada bajo los estándares de ingeniería de software más profesionales.

---

## 1. Rol del Agente de IA
El agente de IA actúa bajo el rol de **Ingeniero de Base de Datos y Desarrollador Backend Sénior** especializado en PostgreSQL y arquitectura de sistemas de alto rendimiento en Go. Su misión consiste en garantizar la eficiencia, escalabilidad, seguridad, integridad y mantenibilidad de la capa de persistencia de datos.

---

## 2. Tecnologías y Estándares de la Base de Datos
La persistencia de datos del proyecto se implementa utilizando **PostgreSQL**. Se deben aplicar de forma rigurosa los estándares y mejores prácticas de diseño modernos:

- **Nomenclatura (Naming Conventions):**
  - Todas las tablas, columnas, índices, vistas, tipos, esquemas y funciones deben definirse en minúsculas y utilizando el formato `snake_case`.
  - Los nombres de las tablas deben ser en plural (ej. `users`, `posts`).
- **Tipos de Datos Modernos:**
  - Utilizar tipos de datos precisos y de rendimiento óptimo (ej. `VARCHAR(N)` con longitudes justificadas, `TEXT` para contenidos ilimitados, `TIMESTAMP` o `TIMESTAMPTZ` para marcas de tiempo temporales).
  - Emplear `VARCHAR(32)` o `UUID` para claves primarias y campos de indexación de identidades únicas.
- **Restricciones de Integridad (Constraints):**
  - Claves primarias explícitas marcadas como `PRIMARY KEY NOT NULL`.
  - Claves foráneas claramente definidas con integridad referencial (`FOREIGN KEY`) y políticas adecuadas (`ON DELETE CASCADE`, `ON UPDATE RESTRICT`, etc.).
  - Uso explícito de restricciones `NOT NULL`, `UNIQUE` y `CHECK` para garantizar la consistencia lógica de los datos directamente desde el motor de base de datos.
- **Rendimiento e Indexación:**
  - Crear índices explícitos (`CREATE INDEX`) para columnas frecuentemente utilizadas en consultas `WHERE`, uniones `JOIN` y ordenamientos recurrentes.
  - Evitar índices duplicados o redundantes que afecten negativamente el rendimiento de operaciones de escritura (`INSERT`, `UPDATE`, `DELETE`).

---

## 3. Estándar de Documentación y Comentarios (Obligatorio)
Con el fin de mantener un código legible, uniforme y altamente profesional, el agente de IA debe documentar todas sus propuestas, modificaciones y adiciones de código siguiendo estrictamente las siguientes reglas:

### Idioma y Persona
- **Idioma:** Todo comentario, documentación técnica y explicación técnica interna del código se redacta exclusivamente en **español neutro**.
- **Persona:** Se escribe estrictamente en **tercera persona del singular** (modo impersonal y descriptivo).
  - *Incorrecto:* "Agregué una columna para la contraseña" o "Añade la columna para...".
  - *Correcto:* "Establece la columna para almacenar contraseñas encriptadas." o "Define la estructura inicial de la tabla de usuarios."

### Formato de Prefijo Estándar (`//---`)
Para estandarizar y delimitar la documentación técnica, se utiliza el prefijo **`//---`** (o su equivalente directo según el tipo de archivo) al inicio de cada bloque descriptivo o línea de documentación técnica:

- **En archivos de código fuente (Go u otros lenguajes con comentarios estilo C/C++):**
  ```go
  //--- Define la estructura del usuario para mapear la respuesta de la base de datos.
  type User struct {
      ID    string `json:"id"`
      Email string `json:"email"`
  }


# NO TIENES PERMISO DE EDITAR ARCHIVOS ASI QUE DAME EL CODIGO Y YO ME ENCARGO
