
## 🧭 Índice

- [1. Tokens personales de Laravel](#1-tokens-personales-de-laravel)
- [2. Pasos básicos para configurar Sanctum en Laravel (protegiendo rutas)](#2-pasos-básicos-para-configurar-sanctum-en-laravel-protegiendo-rutas)
  - [Instalación y migración](#instalación-y-migración)
  - [Realizamos las migraciones](#realizamos-las-migraciones)
  - [Controladores y código para la API](#controladores-y-código-para-la-api)
  - [Controlador Auth](#controlador-auth)
    - [Método login(request request)](#método-loginrequest-request)
    - [Método register(request request)](#método-registerrequest-request)
    - [Método logout(request request)](#método-logoutrequest-request)
  - [Expiración del token](#expiración-del-token)
  - [Creación de rutas y protección](#creación-de-rutas-y-protección)
- [3. Abilities](#3-abilities)
  - [¿Qué son las “abilities” en Sanctum?](#qué-son-las-abilities-en-sanctum)
- [4. Validator](#4-validator)
  - [¿Qué es el Validator en Laravel?](#qué-es-el-validator-en-laravel)
  - [Formas de usar el Validator](#formas-de-usar-el-validator)
    - [1. Con el método validate() en el controlador](#1-con-el-método-validate-en-el-controlador)
    - [2. Con el facade Validator](#2-con-el-facade-validator)


# 1. Tokens personales de Laravel

Aunque Sanctum no usa JWT en su forma “clásica” (como los JWT usados en OAuth o librerías JWT puras), **el concepto de token firmado que representa a un usuario es similar**.

Sanctum proporciona **“personal access tokens”** (tokens de acceso personales) para autenticar peticiones a una API. Internamente, esos tokens están almacenados en una tabla `personal_access_tokens` y llevan información para validar y revocar, entre otras. [Authentication en Laravel.](https://laravel.com/docs/12.x/authentication?utm_source=chatgpt.com)

Cuando la petición llega con ese token (normalmente en el encabezado `Authorization: Bearer <token>`), Sanctum lo valida, recupera el usuario correspondiente y permite la ejecución de la ruta protegida mediante el middleware `auth:sanctum`.

Entonces, aunque no es un JWT puro con partes codificadas en el cliente, desde el punto de vista del cliente se comporta como un token: lo incluyes en cada petición, proteges rutas en el backend, etc.

Sanctum también tiene un modo para SPA (con cookies de sesión), pero para una API REST lo más habitual es usar tokens personales.

---

# 2. Pasos básicos para configurar Sanctum en Laravel (protegiendo rutas)

## Instalación y migración

Desde **Laravel 10**, Sanctum **no viene instalado**, pero el guard `auth:sanctum` ya está preparado en la configuración de `config/auth.php`. Al crear el proyecto con `composer create-project laravel/laravel`, se genera un esqueleto de la aplicación en el que algunos paquetes de “starter kits” podrían venir listados, pero eso no implica que el *framework en sí* incluya esos paquetes. Laravel el framework (el “core”) está separado de la plantilla de aplicación.

| Versión de Laravel | ¿Sanctum viene instalado por defecto? | ¿Incluye soporte nativo? |
| --- | --- | --- |
| **Laravel 7.x** (2020) | ❌ No instalado por defecto | ✅ Soporte oficial introducido |
| **Laravel 8.x** | ❌ No instalado por defecto | ✅ Totalmente compatible |
| **Laravel 9.x** | ❌ No instalado por defecto | ✅ Incluido en `laravel/laravel` como sugerido |
| **Laravel 10.x** | ⚠️ No instalado automáticamente, pero **preconfigurado** (guard `sanctum` ya soportado) |  |
| **Laravel 11.x y 12.x (actual)** | ⚙️ **No instalado**, pero **soporte nativo completo** (solo requiere `composer require laravel/sanctum`) |  |

Como viene preparado no hace falta instalarlo, si quisiéramos hacerlo sería con el comando, dentro de la carpeta del proyecto:

```bash
composer require laravel/sanctum
```

No olvidemos preparar nuestra app para gestionar rutas API:

```bash
php artisan install:api
```

## Realizamos las migraciones.

Antes de realizar las migraciones configuramos en nuestro archivo .env el acceso a la base de datos.

```bash
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=sanctum_25_26
DB_USERNAME=fernando
DB_PASSWORD=
```

Hacemos las migraciones que incorpora automáticamente Laraval, con ello creamos la tabla users y otras tablas que gestionarán los tokenes.

```bash
php artisan migrate
```

Tras hacerlo comprobamos que esta línea use "Laravel\Sanctum\HasApiTokens;" está en el modelo User, quedando:

```php
namespace App\Models;

// use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Sanctum\HasApiTokens;

class User extends Authenticatable
{
    /** @use HasFactory<\Database\Factories\UserFactory> */
    use HasFactory, Notifiable, HasApiTokens;

```

Vamos a hacer una tabla personal que tenga datos que podemos crear y consultar, en este caso partes que ponemos a alumnos. Pocos ponemos…

```php
php artisan make:model Parte -mfs 
```

Con esos parámetros creará la migration, la factory y el seeder asociado, automáticamente.

Configuramos el modelo creado de la siguiente manera:

```php
namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class Parte extends Model
{
    /** @use HasFactory<\Database\Factories\ParteFactory> */
    use HasFactory;

    protected $fillable = [
        'nombre',
        'causa',
        'gravedad'
    ];
}
```

No necesitamos configurar más porque los atributos (sobre id, nombre de la tabla, claves y timestamps) por defecto sirven para este caso.

La migración de esta tabla quedará:

```php
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('partes', function (Blueprint $table) {
            $table->id();
            $table->string('nombre');
            $table->text('causa');
            $table->text('gravedad');
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('partes');
    }
};
```

Migramos de nuevo para incluir esta tabla:

```php
php artisan migrate
```

## Controladores y código para la API.

Hacemos los controladores, uno para la autorización y otro para el CRUD.

```php
php artisan make:controller API/AuthController
php artisan make:controller API/ParteController
```

Añadimos el código del controlador para el parte. Usaremos los nombres habituales para los métodos clásicos de un CRUD.

**Controlador parte.**

```php
namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use App\Models\Parte;
use Illuminate\Http\Request;

class ParteController extends Controller
{
    public function index()
    {
        $partes = Parte::all();
        return response()->json($partes,200);
    }

    public function store(Request $request)
    {
        $input = $request->all();
        $parte = Parte::create($input);
        return response()->json(["success"=>true,"data"=>$parte, "message" => "Created"],201);
    }

    public function show($id)
    {
        $parte = Parte::find($id);
        if (is_null($parte)) {
            return response()->json("Parte no encontrado",404);
        }
        return response()->json(["success"=>true,"data"=>$parte, "message" => "Retrieved"]);
    }

    public function update($id, Request $request)
    {
        $input = $request->all();

        $parte = Parte::find($id);
        if (is_null($parte)) {
            return response()->json(["success"=>false, "message" => "Not found"],404);
        }
        else {
            $parte->nombre = $input['nombre'];
            $parte->causa = $input['causa'];
            $parte->save();

            return response()->json(["success"=>true,"data"=>$parte, "message" => "Updated"]);
        }
    }

    public function destroy($id)
    {
        $parte = Parte::find($id);
        if (is_null($parte)) {
            return response()->json(["success"=>false, "message" => "Not found"],404);
        }
        else {
            $parte->delete();
            return response()->json(["success"=>true,"data"=>$parte, "message" => "Deleted"],200);
        }
    }
}

```

## Controlador Auth

Añadimos el código del controlador para el Auth.

```php
namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        if(Auth::attempt(['email' => $request->email, 'password' => $request->password])){
            $auth = Auth::user();
            // return $auth;
            $tokenResult = $auth->createToken('LaravelSanctumAuth');

            // Actualizar expiración
            // $hours = (int) env('SANCTUM_EXPIRATION_HOURS', 2);
            // $tokenResult->accessToken->expires_at = now()->addHours($hours);
            // $tokenResult->accessToken->save();

            $success = [
                'id'         => $auth->id,
                'name'       => $auth->name,
                'token'      => $tokenResult->plainTextToken,
                'expires_at' => $tokenResult->accessToken->expires_at == null ? null :  $tokenResult->accessToken->expires_at->toDateTimeString()
            ];

            return response()->json(["success"=>true,"data"=>$success, "message" => "User logged-in!"]);
        }
        else{
            return response()->json("Unauthorised",204);
        }
    }

    public function register(Request $request)
    {
        $us = User::where('email',$request->email)->first();
        if(!empty($us->email)) {
            return response()->json(["success"=>false, "message" => "Already registered user"]);
        }
        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);

        $tokenResult = $user->createToken('LaravelSanctumAuth');

        // Actualizar expiración
        // $hours = (int) env('SANCTUM_EXPIRATION_HOURS', 2);
        // $tokenResult->accessToken->expires_at = now()->addHours($hours);
        // $tokenResult->accessToken->save();

        $success = [
            'id' => $user->id,
            'name' => $user->name,
            'token' => $user->createToken('LaravelSanctumAuth')->plainTextToken,
            'expires_at' => $tokenResult->accessToken->expires_at ==null ? null:  $tokenResult->accessToken->expires_at->toDateTimeString()
        ];

        return response()->json(["success"=>true,"data"=>$success, "message" => "User successfully registered!"]);
    }

     /**
     * Por defecto los tokens de Sanctum no expiran. Se puede modificar esto añadiendo una cantidad en minutos a la variable 'expiration' en el archivo de config/sanctum.php.
     */
     public function logout(Request $request)
    {
        if(Auth::attempt(['email' => $request->email, 'password' => $request->password])){
            $cantidad = Auth::user()->tokens()->delete();
            return response()->json(["success"=>true, "message" => "Tokens Revoked: ".$cantidad],200);
        }
        else {
            return response()->json("Unauthorised",204);
        }

    }
}
```

### Método `login(Request $request)`

**Propósito:** autenticar a un usuario existente y devolver un **token de acceso personal** para usarlo en peticiones protegidas.

**Funcionamiento paso a paso:**

1. **Validación de credenciales:**

```php
Auth::attempt(['email' => $request->email, 'password' => $request->password])
```

- 
    - Laravel verifica si existe un usuario con el email proporcionado y si la contraseña coincide.
    - Retorna `true` si las credenciales son correctas, `false` en caso contrario.

**2. Obtener datos del usuario autenticado:**

```php
$auth = Auth::user();
```

1. **Generar token con Sanctum:**

```php
$auth->createToken('LaravelSanctumAuth')->plainTextToken
```

- Crea un **token personal** que el cliente usará en el header `Authorization: Bearer <token>` para acceder a rutas protegidas.
- `plainTextToken` devuelve el token en texto plano (solo se muestra una vez).
1. **Devolver respuesta JSON:**
    - Si las credenciales son correctas:

```php
{
  "success": true,
  "data": {
    "id": 1,
    "name": "Juan",
    "token": "xxx"
  },
  "message": "User logged-in!"
}
```

- Si fallan las credenciales: responde con `"Unauthorised"` y código HTTP 204.

### Método `register(Request $request)`

**Propósito:** registrar un nuevo usuario y devolver un **token de acceso personal** al momento de la creación.

**Funcionamiento paso a paso:**

1. **Verificar si el usuario ya existe:**

```php
$us = User::where('email', $request->email)->first();
if(!empty($us->email)) {
    return response()->json(["success"=>false, "message" => "Already registered user"]);
}
```

- 
    - Evita registros duplicados.
1. **Preparar los datos del nuevo usuario:**

```php
$input = $request->all();
$input['password'] = bcrypt($input['password']);
```

- 
    - La contraseña se **encripta** con `bcrypt()` para almacenarla de manera segura.
1. **Crear el usuario en la base de datos:**

```php
$user = User::create($input);
```

1. **Generar token de acceso con Sanctum:**

```php
$user->createToken('LaravelSanctumAuth')->plainTextToken
```

- El token se entrega inmediatamente al cliente recién registrado.
1. **Devolver respuesta JSON:**
- Incluye los datos del usuario y el token.

### Método `logout(Request $request)`

**Propósito:** revocar todos los tokens de un usuario, cerrando su sesión en la API.

**Funcionamiento paso a paso:**

1. **Verificar credenciales (opcional en este caso):**

```php
Auth::attempt(['email' => $request->email, 'password' => $request->password])
```

- Confirma que la persona que pide logout es realmente el usuario correcto.
1. **Eliminar todos los tokens del usuario:**

```php
Auth::user()->tokens()->delete();
```

- Esto **revoca todos los tokens activos**, por lo que cualquier petición futura con esos tokens será rechazada.
1. **Devolver respuesta JSON:**

```php
{
  "success": true,
  "message": "Tokens Revoked: 3"
}
```

- Indica cuántos tokens fueron eliminados.

**Nota importante:**

- Por defecto, los **tokens de Sanctum no expiran**, pero se puede configurar en `config/sanctum.php` con la variable `expiration` (en minutos).
- Otra alternativa es asignar expiración manual a cada token usando un campo `expires_at`.

### Expiración del token.

1. Laravel Sanctum permite establecer una expiración global que afectará a **todos los tokens** que se creen con `createToken()`.
- **Configurar en `config/sanctum.php`**:

```php
'expiration' => env('SANCTUM_EXPIRATION', null), // en minutos
```

- En `.env` puedes poner, por ejemplo:

```php
SANCTUM_EXPIRATION=120
```

- Esto significa que **todos los tokens caducan después de 120 minutos** (2 horas).
- `null` → los tokens **no caducan**.
- **Ejemplo de uso global**:

```php
$tokenResult = $user->createToken('LaravelSanctumAuth');
// Laravel aplicará automáticamente la expiración global configurada
```

2. Configuración individual por token.

Puedes establecer una expiración **solo para un token concreto, el ejemplo de clase:**

```php
$tokenResult = $auth->createToken('LaravelSanctumAuth');

// Actualizar expiración
$hours = (int) env('SANCTUM_EXPIRATION_HOURS', 2);
$tokenResult->accessToken->expires_at = now()->addHours($hours);
$tokenResult->accessToken->save();

//siendo en .env:
SANCTUM_EXPIRATION_HOURS=3
```

- Solo este token caduca en 3 horas (caso de no estar la variable de entorno le asigna un 2).
- Otros tokens del mismo usuario **no se ven afectados**.
- Permite crear tokens con **diferentes duraciones según necesidad** (por ejemplo, “recordarme” tokens más largos vs tokens temporales de API).

## Creación de rutas y protección.

Añadimos las rutas.

```php
use App\Http\Controllers\API\AuthController;
use App\Http\Controllers\API\ParteController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::middleware('auth:sanctum')->group( function () {
    Route::get('partes', [ParteController::class,'index']);
    Route::post('parte', [ParteController::class,'store']);
    Route::get('parte/{id}', [ParteController::class,'show']);
    Route::put('parte/{id}', [ParteController::class,'update']);
    Route::delete('parte/{id}', [ParteController::class,'destroy']);
});

Route::post('login', [AuthController::class, 'login']);
Route::post('logout', [AuthController::class, 'logout']);
Route::post('register', [AuthController::class, 'register']);
```

Vemos que las rutas que manejan el CRUD de los partes está protegida por sanctum. Si no existe un token correcto, activo y bien formado no se permitirá el acceso a las rutas incluidas en el grupo.

Podemos observar que las rutas para hacer login, registro y logout están sin proteger porque deben ser accesibles antes de estar en el sistema, claro.

Vemos que cuando intentamos acceder a una ruta no autorizada salta un error porque trata de llevarnos a la ruta login, que no existe. Esto es porque cuando no tenemos token Laravel nos lleva a una ruta `nologin`, que no hemos definido en nuestras rutas. 

Para controlar este error añadimos la línea:

```php
$middleware->redirectGuestsTo('/api/nologin');
```

En el registro de middlewares `bootstrap/app.php`

```php
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->redirectGuestsTo('/api/nologin');
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        //
    })->create();
```

Y creamos la ruta no login en la API:

```php
Route::get('/nologin', function () {
    return response()->json(["success"=>false, "message" => "Unauthorised"],203);
});

```

# 3. Abilities

## ¿Qué son las “abilities” en Sanctum?

- Cuando usas Sanctum para emitir *tokens de acceso personal* (personal access tokens), puedes asignar a cada token un conjunto de permisos — llamadas *abilities*. [DEV Community+3jetstream.laravel.com+3freek.dev+3](https://jetstream.laravel.com/features/api.html?utm_source=chatgpt.com)
- Estas abilities permiten restringir **qué acciones puede realizar ese token**. En vez de “el usuario puede hacer todo”, puedes decir “este token sólo puede leer posts”, o “este otro token puede crear y borrar posts”. [Redberry International+1](https://redberry.international/laravel-sanctum-easy-authentication/?utm_source=chatgpt.com)
- No confundir con roles complejos (aunque se puede usar para ello): es más liviano, diseñado para controlar el acceso de tokens. [Amezmo+1](https://www.amezmo.com/laravel-hosting-guides/role-based-api-authentication-with-laravel-sanctum?utm_source=chatgpt.com)

¿Cómo se usan? – Flujo básico

Se añaden al token cuando se crean:

```php
$tokenResult = $auth->createToken('LaravelSanctumAuth', ['read', 'delete','mindundi']);
```

Se protegen usando un middleware para la ruta:

```php
Route::get('parte/{id}', [ParteController::class,'show'])
     ->middleware(['midread','midmindundi']);
```

Siendo estos middlewares:

```php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class MidRead
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();
        if ($user->tokenCan("read")) {
           return $next($request);
        }
        else {
            return response()->json(["success"=>false, "message" => "No autorizado"],202);
        }
    }
}
```

Y:

```php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class MidMindundi
{
    /**
     * Handle an incoming request.
     *
     * @param  \Closure(\Illuminate\Http\Request): (\Symfony\Component\HttpFoundation\Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();
        if ($user->tokenCan("mindundi")) {
           return $next($request);
        }
        else {
            return response()->json(["success"=>false, "message" => "No autorizado"],202);
        }
    }
}
```

Registrando los middleware en bootstrap/app:

```php
use App\Http\Middleware\MidAdmin;
use App\Http\Middleware\MidDelete;
use App\Http\Middleware\MidMindundi;
use App\Http\Middleware\MidRead;
use App\Http\Middleware\MidUpdate;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\AuthenticationException;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\JsonResponse;
use Laravel\Sanctum\Exceptions\MissingAbilityException;
use Laravel\Sanctum\Http\Middleware\CheckAbilities;
use Laravel\Sanctum\Http\Middleware\CheckForAnyAbility;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__ . '/../routes/web.php',
        api: __DIR__ . '/../routes/api.php',
        commands: __DIR__ . '/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->alias([
            'todas' => CheckAbilities::class,
            'alguna' => CheckForAnyAbility::class,
            'mid1' => Mid1::class,
            'midread' => MidRead::class,
            'midupdate' => MidUpdate::class,
            'middelete' => MidDelete::class,
            'midadmin' => MidAdmin::class,
            'midmindundi' => MidMindundi::class,
        ]);

        // Redirección de usuarios no autenticados (solo para rutas web)
        $middleware->redirectGuestsTo('/api/nologin');
    })
    ->withExceptions(function (\Illuminate\Foundation\Configuration\Exceptions $exceptions): void {
        // Manejo personalizado de excepciones para respuestas JSON en rutas API
    })->create();
```

Podemos observar que existen los casos de ‘todas’ o ‘alguna’ que se pasarían así en las rutas:

```php
    Route::get('partes', [ParteController::class,'index'])
    //->middleware('alguna:read,update');
    ->middleware('todas:read,update');
```

Harían justo eso, pasan el middleware si el token tiene alguno o todos los permisos asignados.

# 4. Validator

## 🧩 ¿Qué es el *Validator* en Laravel?

El *Validator* es el **sistema de validación de datos** que usa Laravel para asegurarse de que los datos enviados (por formularios, peticiones API, etc.) cumplan ciertas reglas antes de procesarlos.

👉 Se encuentra en la clase `Illuminate\Support\Facades\Validator`.

## 🧠 Formas de usar el *Validator*

Laravel permite validar de **tres maneras principales**:

### 1. Con el método `validate()` en el controlador

La forma más simple (Laravel hace todo por ti):

```php
public function store(Request $request)
{
    $validated = $request->validate([
        'name' => 'required|string|max:255',
        'email' => 'required|email|unique:users',
        'age' => 'nullable|integer|min:18',
    ]);

    // Si pasa la validación, continúa
    User::create($validated);
}
```

🔹 Si la validación falla, Laravel redirige automáticamente (en web) o devuelve errores en JSON (en API).

---

### 2. Con el *facade* `Validator`

Permite más control manual (útil en APIs o validaciones complejas):

```php
use Illuminate\Support\Facades\Validator;

public function store(Request $request)
{
    $validator = Validator::make($request->all(), [
        'title' => 'required|min:5',
        'content' => 'required',
    ]);

    if ($validator->fails()) {
        return response()->json(['errors' => $validator->errors()], 422);
    }

    Post::create($validator->validated());
}
```

🔹 Puedes usar `$validator->fails()`, `$validator->errors()` y `$validator->validated()`.

🧾 Reglas de validación más comunes

| Regla | Descripción |
| --- | --- |
| `required` | El campo es obligatorio |
| `string`, `integer`, `numeric`, `boolean`, `array` | Tipo de dato |
| `min:value`, `max:value` | Longitud o valor mínimo/máximo |
| `email`, `url`, `date` | Formato específico |
| `unique:table,column` | Debe ser único en la tabla |
| `exists:table,column` | Debe existir en la tabla |
| `confirmed` | Necesita otro campo igual (por ejemplo `password_confirmation`) |
| `nullable` | Campo puede ser nulo |
| `sometimes` | Solo valida si el campo está presente |
| `in:a,b,c` / `not_in:x,y,z` | Valores permitidos o no permitidos |
| `regex:/pattern/` | Usa una expresión regular |
| `after:today`, `before_or_equal:now` | Fechas relativas |

🧩 Validación de arrays y objetos anidados

```php
$request->validate([
    'users' => 'required|array',
    'users.*.name' => 'required|string',
    'users.*.email' => 'required|email',
]);

```

🔹 `*` significa “para cada elemento del array”.

⚙️ Mensajes personalizados

```php
$request->validate([
    'email' => 'required|email'
], [
    'email.required' => 'El correo es obligatorio',
    'email.email' => 'Debe ser un correo válido',
]);
```

También puedes definirlos globalmente en `resources/lang/es/validation.php`.

🧰 Métodos útiles del objeto `Validator`

| Método | Descripción |
| --- | --- |
| `$validator->fails()` | Retorna `true` si falla |
| `$validator->passes()` | Retorna `true` si pasa |
| `$validator->errors()` | Retorna errores |
| `$validator->validated()` | Devuelve solo los datos válidos |
| `$validator->setData($data)` | Cambia los datos a validar |
| `$validator->sometimes($field, $rules, $callback)` | Agrega reglas condicionales |

En el ejemplo de clase, podemos poner las reglas siguiente, en Auth:

```php
public function register(Request $request)
    {
        // $us = User::where('email',$request->email)->first();
        // if(!empty($us->email)) {
        //     return response()->json(["success"=>false, "message" => "Already registered user"]);
        // }
        $input = $request->all();
        $rules = [
            'name' => 'required|string|max:20',
            'email' => 'required|email|max:255|unique:users',
            'password' => 'required|min:8',
            'confirm_password' => 'required|same:password',
            'edad' => 'required|integer|between:18,190'
        ];
        $messages = [
            'unique' => 'El :attribute ya está registrado en la base de datos.',
            'email' => 'El campo :attribute debe ser un correo electrónico válido.',
            'same' => 'El campo :attribute y :other deben coincidir.',
            'max' => 'El campo :attribute no debe exceder el tamaño máximo permitido.',
            'between' => 'El campo :attribute debe estar entre :min y :max años.',
            'integer' => 'El campo :attribute debe ser un número entero.',
            'required' => 'El campo :attribute es obligatorio.'
        ];

        $validator = Validator::make($request->all(), $rules, $messages);
        if($validator->fails()){
            return response()->json($validator->errors(),422);
        }

        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);
        // $success['token'] =  $user->createToken('LaravelSanctumAuth')->plainTextToken;
        // $success['name'] =  $user->name;
        $success = [
            'token' => $user->createToken('LaravelSanctumAuth')->plainTextToken,
            'name' => $user->name,
            'id' => $user->id
        ];

        return response()->json(["success"=>true,"data"=>$success, "message" => "User successfully registered!"]);
    }
```

Y en partes:

```php
    public function store(Request $request)
    {
        $input = $request->all();

        $rules = [
            'nombre' => 'required|string|max:255',
            'causa' => 'required|in:Nada,Todo,"Me tiene mania"',
            'gravedad' => 'required|in:Leve,Destierro,"Pasar por la quilla"',
            // 'observaciones' => 'required|string|max:255'
        ];
        $messages = [
            'required' => 'El campo :attribute es obligatorio.',
            'in' => 'El campo :attribute debe ser uno de los siguientes valores: :values.'
        ];

        $validator = Validator::make($input, $rules, $messages);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
        $parte = Parte::create($input);
        return response()->json(["success"=>true,"data"=>$parte, "message" => "Created"]);
    }
```
