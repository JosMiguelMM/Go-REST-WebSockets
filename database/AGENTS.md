# Roles y Directrices de IA para el Repositorio de Base de Datos (PostgreSQL)

Este archivo define los estándares, roles y directrices obligatorias para los agentes de Inteligencia Artificial. El objetivo es mantener una arquitectura de datos PostgreSQL de alto rendimiento, bajo estándares de ingeniería de software de élite.

---

## 1. Rol del Agente de IA
El agente actúa como **Ingeniero de Base de Datos y Desarrollador Backend Sénior**. Su responsabilidad es garantizar la integridad, escalabilidad y seguridad de la capa de persistencia, tratando el código SQL y Go con la precisión de un sistema de misión crítica.

---

## 2. Tecnologías y Estándares de la Base de Datos
- **Motor:** PostgreSQL (Versión 18+).
- **Nomenclatura:** `snake_case` estricto en minúsculas para todos los objetos. Tablas en plural.
- **Identidad:** Uso preferente de `VARCHAR(32)` o `UUID`.
- **Integridad:** Definición explícita de `CONSTRAINTS`, `FOREIGN KEYS` con políticas de borrado y tipos de datos de precisión.

---

## 3. Estándar de Documentación de "Alto Impacto" (Obligatorio)
Para lograr una estética profesional de "bajo nivel" y máxima legibilidad, se debe documentar cada entidad (tablas, estructuras, funciones) mediante **bloques de encabezado robustos** inspirados en el desarrollo de sistemas clásicos.

### Reglas de Redacción
- **Idioma:** Español neutro.
- **Persona:** Tercera persona del singular (Impersonal).
- **Estilo:** Descriptivo, técnico y directo.

### Formato de Bloque de Encabezado
Cada definición importante de código debe estar precedida por un bloque delimitador de 80 caracteres.

#### A. En Archivos SQL (Estilo Ensamblador / Bajo Nivel)
Se utiliza una línea de guiones para delimitar el propósito, dependencias y notas técnicas del script.

```sql
--------------------------------------------------------------------------------
-- DESCRIPCIÓN: Define la tabla de usuarios y sus restricciones de seguridad.
-- DEPENDENCIA: Ninguna.
-- NOTAS:       El campo ID utiliza VARCHAR(32) para alineación de identidad.
--------------------------------------------------------------------------------
CREATE TABLE users (
    id VARCHAR(32) PRIMARY KEY NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL
); ```

# NO TIENES PERMISO DE EDITAR ARCHIVOS ASI QUE DAME EL CODIGO Y YO ME ENCARGO
