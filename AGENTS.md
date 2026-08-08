# Reglas de Desarrollo para Proyecto Go

## 📖 Estándares de Documentación (Golang Docs)
### Comentarios para Funciones
```go
// Obtiene un usuario por su ID desde la base de datos
//
// Parámetros:
//   - id int: Identificador único del usuario
// 
// Retornos:
//   - *User: Puntero al objeto User encontrado
//   - error: nil si operación fue exitosa, error en caso contrario
func GetUser(id int) (*User, error) {
    // Lógica de obtención del usuario
}
```

### Comentarios para Estructuras
```go
// Representa un usuario con sus atributos básicos
//
// Campos:
//   - ID: Identificador único del usuario (entero positivo)
//   - Nombre: Nombre completo del usuario (máximo 100 caracteres)
//   - Email: Correo electrónico validado (formato RFC 5322)
type User struct {
    ID    int
    Name  string
    Email string
}
```

### Comentarios para Constantes/Variables
```go
// MaxUsuarios es el límite máximo de usuarios permitidos en el sistema
const MaxUsuarios = 1000

// TimeoutConexion define el tiempo máximo para establecer una conexión WebSocket
var TimeoutConexion = time.Second * 5
```

## ⚡ Optimización de Recursos
### Ejemplo de Uso de sync.Pool
```go
type Pool struct {
    pool sync.Pool
}

func (p *Pool) Get() interface{} {
    return p.pool.Get()
}

func (p *Pool) Put(x interface{}) {
    p.pool.Put(x)
}
```

### Ejemplo de Bufferización eficiente
```go
buffer := &bytes.Buffer{}
buffer.WriteString("Hola ")
buffer.Write([]byte("mundo"))
fmt.Println(buffer.String())
```

## 🔐 Prácticas de Seguridad
### Manejo de Errores con Wrapping
```go
if err != nil {
    return fmt.Errorf("error al obtener usuario: %w", err)
}
```

### Validación de Entrada
```go
if len(input) > 1024 {
    return errors.New("entrada demasiado larga")
}
```

## 🧠 Buena Práctica de Código
### Uso de Contexto para Request-Scoped Data
```go
ctx := context.WithValue(context.Background(), "user", currentUser)
result, err := ProcessRequest(ctx)
```

### Patrón de Diseño Factory
```go
func NewUserService(db *DB) *UserService {
    return &UserService{
        db: db,
    }
}
