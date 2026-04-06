import { next } from '@vercel/functions';

const REALM = 'Protected AWS Guide';
const PASSWORD_ENV_NAME = 'GUIDE_BASIC_AUTH_PASSWORD';

function unauthorizedResponse() {
  return new Response(
    `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authentication Required</title>
  <style>
    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: #09111f;
      color: #e2e8f0;
      font-family: Arial, sans-serif;
    }
    .panel {
      width: min(92vw, 540px);
      padding: 28px;
      border-radius: 16px;
      border: 1px solid rgba(125, 211, 252, 0.2);
      background: rgba(15, 23, 42, 0.96);
      box-shadow: 0 24px 70px rgba(0, 0, 0, 0.35);
    }
    h1 {
      margin: 0 0 12px;
      font-size: 1.5rem;
    }
    p {
      margin: 0;
      color: #94a3b8;
      line-height: 1.6;
    }
    code {
      color: #7dd3fc;
    }
  </style>
</head>
<body>
  <main class="panel">
    <h1>Password Required</h1>
    <p>This guide is protected with HTTP Basic Auth on Vercel middleware.</p>
    <p>When your browser prompts you, use any username and the configured deployment password.</p>
  </main>
</body>
</html>`,
    {
      status: 401,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'www-authenticate': `Basic realm="${REALM}", charset="UTF-8"`,
        'cache-control': 'no-store',
      },
    }
  );
}

function missingPasswordResponse() {
  return new Response(
    `Missing required environment variable: ${PASSWORD_ENV_NAME}`,
    {
      status: 503,
      headers: {
        'content-type': 'text/plain; charset=utf-8',
        'cache-control': 'no-store',
      },
    }
  );
}

function isAuthorized(request) {
  const expectedPassword = process.env[PASSWORD_ENV_NAME];
  if (!expectedPassword) return false;

  const authHeader = request.headers.get('authorization');
  if (!authHeader || !authHeader.startsWith('Basic ')) return false;

  const encodedCredentials = authHeader.slice(6).trim();
  let decodedCredentials = '';

  try {
    decodedCredentials = atob(encodedCredentials);
  } catch {
    return false;
  }

  const separatorIndex = decodedCredentials.indexOf(':');
  if (separatorIndex === -1) return false;

  const password = decodedCredentials.slice(separatorIndex + 1);
  return password === expectedPassword;
}

export default function middleware(request) {
  if (!process.env[PASSWORD_ENV_NAME]) {
    return missingPasswordResponse();
  }

  if (isAuthorized(request)) {
    return next();
  }

  return unauthorizedResponse();
}

export const config = {
  matcher: [
    '/((?!_vercel|api).*)',
  ],
};
