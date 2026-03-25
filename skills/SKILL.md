---
name: laravel-sanctum-api-auth
description: "Laravel Sanctum API authentication — token-based auth, SPA authentication, mobile app tokens, token abilities/scopes, rate limiting, and multi-guard setups. Use when implementing API authentication, issuing personal access tokens, setting up SPA cookie-based auth, protecting API routes, managing token abilities, revoking tokens, or building login/register/logout API endpoints. Triggers on tasks involving Sanctum setup, Bearer token auth, token scoping, API middleware, SPA CSRF cookie, mobile app authentication, or any Laravel API auth flow. Use PROACTIVELY whenever API authentication, tokens, or Sanctum is mentioned."
compatible_agents:
  - Claude Code
  - Cursor
  - Windsurf
  - Copilot
tags:
  - laravel
  - sanctum
  - api
  - authentication
  - tokens
  - spa
  - security
  - php
---

# Laravel Sanctum API Authentication

Sanctum provides two authentication systems: token-based auth for APIs/mobile apps, and cookie-based SPA auth. Choose based on your client type.

## Setup

```bash
composer require laravel/sanctum
php artisan install:api
# Adds: api.php routes, Sanctum migrations, HasApiTokens trait
```

## Token-Based Auth (APIs & Mobile)

### Registration & Login

```php
// app/Http/Controllers/Api/AuthController.php
namespace App\Http\Controllers\Api;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    public function register(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users',
            'password' => 'required|string|min:8|confirmed',
            'device_name' => 'required|string',
        ]);

        $user = User::create([
            'name' => $validated['name'],
            'email' => $validated['email'],
            'password' => Hash::make($validated['password']),
        ]);

        $token = $user->createToken(
            $validated['device_name'],
            ['*'], // abilities
            now()->addDays(30), // expiration
        );

        return response()->json([
            'user' => $user,
            'token' => $token->plainTextToken,
        ], 201);
    }

    public function login(Request $request): JsonResponse
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
            'device_name' => 'required|string',
        ]);

        $user = User::where('email', $request->email)->first();

        if (! $user || ! Hash::check($request->password, $user->password)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $token = $user->createToken(
            $request->device_name,
            ['*'],
            now()->addDays(30),
        );

        return response()->json([
            'user' => $user,
            'token' => $token->plainTextToken,
        ]);
    }

    public function logout(Request $request): JsonResponse
    {
        // Revoke current token
        $request->user()->currentAccessToken()->delete();

        return response()->json(['message' => 'Logged out']);
    }

    public function logoutAll(Request $request): JsonResponse
    {
        // Revoke ALL tokens for the user
        $request->user()->tokens()->delete();

        return response()->json(['message' => 'All sessions revoked']);
    }

    public function user(Request $request): JsonResponse
    {
        return response()->json($request->user());
    }
}
```

### Routes

```php
// routes/api.php
use App\Http\Controllers\Api\AuthController;

Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);

Route::middleware('auth:sanctum')->group(function () {
    Route::get('/user', [AuthController::class, 'user']);
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::post('/logout-all', [AuthController::class, 'logoutAll']);

    // Protected API routes
    Route::apiResource('posts', PostController::class);
});
```

## Token Abilities (Scopes)

```php
// Issue token with specific abilities
$token = $user->createToken('api-token', ['posts:read', 'posts:write']);

// Issue read-only token
$readOnlyToken = $user->createToken('read-only', ['posts:read']);

// Check abilities in controller
public function store(Request $request): JsonResponse
{
    if (! $request->user()->tokenCan('posts:write')) {
        abort(403, 'Token does not have write access.');
    }

    // ...create post
}

// Check via middleware
Route::post('/posts', [PostController::class, 'store'])
    ->middleware('ability:posts:write');

Route::get('/posts', [PostController::class, 'index'])
    ->middleware('abilities:posts:read,posts:list'); // ALL required
```

## SPA Cookie Authentication

For first-party SPAs (Vue, React) on the same domain — uses cookies, not tokens.

```php
// config/sanctum.php
'stateful' => explode(',', env('SANCTUM_STATEFUL_DOMAINS',
    'localhost,localhost:3000,localhost:5173,127.0.0.1'
)),
```

```typescript
// SPA client setup
axios.defaults.withCredentials = true;
axios.defaults.withXSRFToken = true;

// Step 1: Get CSRF cookie
await axios.get('/sanctum/csrf-cookie');

// Step 2: Login (session-based)
await axios.post('/login', { email, password });

// Step 3: Access protected routes (cookie sent automatically)
const { data } = await axios.get('/api/user');
```

## Rate Limiting

```php
// app/Providers/AppServiceProvider.php
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Support\Facades\RateLimiter;

public function boot(): void
{
    RateLimiter::for('api', function (Request $request) {
        return Limit::perMinute(60)->by($request->user()?->id ?: $request->ip());
    });

    RateLimiter::for('auth', function (Request $request) {
        return Limit::perMinute(5)->by($request->ip());
    });
}

// Apply to routes
Route::post('/login', [AuthController::class, 'login'])
    ->middleware('throttle:auth');
```

## Key Rules

1. Always set token expiration — `createToken($name, $abilities, $expiry)` — open-ended tokens are a security risk
2. Always hash passwords with `Hash::make()` — never store plaintext
3. Always validate `device_name` on token creation — helps users identify and revoke specific sessions
4. Always use `currentAccessToken()->delete()` for logout — not `tokens()->delete()` (which kills all sessions)
5. Always use abilities for granular access control — `['read', 'write']` not just `['*']`
6. Always rate-limit auth endpoints — prevents brute force (5/min for login, 3/min for register)
7. Use SPA auth (cookies) for first-party frontends — more secure than storing tokens in localStorage
8. Always return consistent JSON error responses — use `ValidationException` not raw responses
9. Never expose tokens in URLs — always use `Authorization: Bearer` header
10. Always prune expired tokens — schedule `sanctum:prune-expired` daily
