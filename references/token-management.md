# Token Management & Security

## Token Rotation

```php
class AuthController extends Controller
{
    public function refreshToken(Request $request): JsonResponse
    {
        $user = $request->user();
        $currentToken = $user->currentAccessToken();

        // Delete old token
        $currentToken->delete();

        // Issue new token with same abilities
        $newToken = $user->createToken(
            $currentToken->name,
            $currentToken->abilities,
            now()->addDays(30),
        );

        return response()->json([
            'token' => $newToken->plainTextToken,
        ]);
    }
}
```

## List Active Sessions

```php
public function sessions(Request $request): JsonResponse
{
    $tokens = $request->user()->tokens()
        ->select(['id', 'name', 'last_used_at', 'created_at', 'expires_at'])
        ->orderByDesc('last_used_at')
        ->get()
        ->map(fn ($token) => [
            'id' => $token->id,
            'device' => $token->name,
            'last_used' => $token->last_used_at?->diffForHumans(),
            'created' => $token->created_at->diffForHumans(),
            'is_current' => $token->id === $request->user()->currentAccessToken()->id,
            'expired' => $token->expires_at?->isPast() ?? false,
        ]);

    return response()->json(['sessions' => $tokens]);
}

public function revokeSession(Request $request, int $tokenId): JsonResponse
{
    $request->user()->tokens()->where('id', $tokenId)->delete();

    return response()->json(['message' => 'Session revoked']);
}
```

## Prune Expired Tokens

```php
// app/Console/Kernel.php
$schedule->command('sanctum:prune-expired --hours=24')->daily();
```

## Token Abilities Middleware

```php
// routes/api.php

// Require specific ability
Route::get('/posts', [PostController::class, 'index'])
    ->middleware(['auth:sanctum', 'ability:posts:read']);

// Require ALL abilities
Route::post('/posts', [PostController::class, 'store'])
    ->middleware(['auth:sanctum', 'abilities:posts:read,posts:write']);
```

## Admin vs User Tokens

```php
// Different abilities for different roles
public function login(Request $request): JsonResponse
{
    // ... authenticate user

    $abilities = match ($user->role) {
        'admin' => ['*'],
        'editor' => ['posts:read', 'posts:write', 'media:upload'],
        'viewer' => ['posts:read'],
        default => ['profile:read'],
    };

    $token = $user->createToken($request->device_name, $abilities, now()->addDays(30));

    return response()->json(['token' => $token->plainTextToken]);
}
```

## Security Best Practices

```php
// Never log or expose tokens
Log::info('User logged in', ['user_id' => $user->id]); // Good
Log::info('User logged in', ['token' => $token]); // BAD

// Always use HTTPS in production
// config/sanctum.php
'guard' => ['web'],
'expiration' => 43200, // 30 days in minutes
```
