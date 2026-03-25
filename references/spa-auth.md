# SPA Cookie Authentication

## How SPA Auth Works

1. Client requests CSRF cookie from `/sanctum/csrf-cookie`
2. Client sends login POST with credentials (cookie-based session created)
3. Subsequent requests include session cookie automatically
4. No tokens stored in localStorage (more secure)

## Backend Configuration

```php
// config/sanctum.php
'stateful' => explode(',', env('SANCTUM_STATEFUL_DOMAINS',
    'localhost,localhost:3000,localhost:5173,127.0.0.1,127.0.0.1:8000,::1'
)),

// config/cors.php
'paths' => ['api/*', 'sanctum/csrf-cookie', 'login', 'logout'],
'supports_credentials' => true,
```

```env
SESSION_DRIVER=redis
SESSION_DOMAIN=.yourdomain.com
SANCTUM_STATEFUL_DOMAINS=yourdomain.com,app.yourdomain.com
```

## Frontend (Axios)

```typescript
import axios from 'axios';

const api = axios.create({
    baseURL: 'https://api.yourdomain.com',
    withCredentials: true,
    withXSRFToken: true,
    headers: { 'Accept': 'application/json' },
});

// Login flow
async function login(email: string, password: string) {
    // Step 1: Get CSRF cookie
    await api.get('/sanctum/csrf-cookie');

    // Step 2: Login
    await api.post('/login', { email, password });

    // Step 3: Fetch user (cookie sent automatically)
    const { data } = await api.get('/api/user');
    return data;
}

async function logout() {
    await api.post('/logout');
}
```

## Backend Auth Routes

```php
// routes/web.php (NOT api.php — SPA auth uses session)
Route::post('/login', function (Request $request) {
    $credentials = $request->validate([
        'email' => 'required|email',
        'password' => 'required',
    ]);

    if (! Auth::attempt($credentials)) {
        throw ValidationException::withMessages([
            'email' => ['The provided credentials are incorrect.'],
        ]);
    }

    $request->session()->regenerate();

    return response()->json($request->user());
});

Route::post('/logout', function (Request $request) {
    Auth::guard('web')->logout();
    $request->session()->invalidate();
    $request->session()->regenerateToken();

    return response()->noContent();
})->middleware('auth');
```

## Common Pitfalls

```
1. CORS: Must set supports_credentials = true
2. Session domain: Must match between API and SPA (.yourdomain.com)
3. HTTPS: Required in production for secure cookies
4. Stateful domains: Must include the SPA's domain
5. Routes: Login/logout go in web.php (session), not api.php
```
