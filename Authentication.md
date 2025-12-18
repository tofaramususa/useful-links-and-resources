# Comprehensive Authentication Implementation Report
## Better-Auth Codebase Analysis

**Version:** 1.4.2-beta.1
**Analysis Date:** 2025-11-24
**Repository:** better-auth

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Core Architecture](#core-architecture)
3. [Session Management](#session-management)
4. [Password Security](#password-security)
5. [CSRF Protection](#csrf-protection)
6. [Rate Limiting](#rate-limiting)
7. [OAuth & Social Authentication](#oauth--social-authentication)
8. [Email Verification](#email-verification)
9. [Two-Factor Authentication](#two-factor-authentication)
10. [Passkeys & WebAuthn](#passkeys--webauthn)
11. [Magic Links](#magic-links)
12. [Organization & Multi-Tenancy](#organization--multi-tenancy)
13. [Single Sign-On (SSO/SAML)](#single-sign-on-ssosaml)
14. [Account Management](#account-management)
15. [Multiple Sessions](#multiple-sessions)
16. [Bearer Token Authentication](#bearer-token-authentication)
17. [API Key Authentication](#api-key-authentication)
18. [Anonymous Authentication](#anonymous-authentication)
19. [Email OTP](#email-otp)
20. [Phone Number Authentication](#phone-number-authentication)
21. [Plugin Architecture](#plugin-architecture)
22. [Client SDK](#client-sdk)
23. [Framework Integration](#framework-integration)
24. [Cryptographic Implementations](#cryptographic-implementations)
25. [Database Layer](#database-layer)
26. [Error Handling](#error-handling)
27. [Security Headers & CORS](#security-headers--cors)
28. [Production Deployment](#production-deployment)
29. [Security Best Practices](#security-best-practices)

---

## Executive Summary

Better-Auth is a production-ready, framework-agnostic authentication framework for TypeScript implementing comprehensive security practices across 20+ authentication methods.

### Key Features

- **Framework-Agnostic**: Next.js, SvelteKit, Solid Start, TanStack Start, Node.js
- **Database-Agnostic**: Prisma, Drizzle, Kysely, MongoDB adapters
- **Type-Safe**: Full TypeScript with automatic type inference
- **Plugin-Based**: 20+ official plugins for extensibility
- **Production-Ready**: Defense-in-depth security at every layer

### Core Security

✅ Scrypt password hashing
✅ HMAC-signed cookies
✅ CSRF protection (SameSite + origin validation)
✅ Rate limiting with Redis support
✅ Constant-time comparisons
✅ PKCE for OAuth
✅ JWT/JWE session caching
✅ XSS prevention

---

## Core Architecture

### File Structure

```
better-auth/
├── packages/
│   ├── better-auth/       # Main library
│   ├── core/              # Core functionality
│   ├── passkey/           # WebAuthn plugin
│   ├── sso/               # SAML/SSO plugin
│   └── expo/              # React Native support
```

### Request Flow

```
Client → Framework Handler → better-call Router → Rate Limiter
  → CSRF Middleware → Plugin Middleware → Endpoint Handler
  → Database → After Hooks → Response
```

### Endpoint Creation

**File:** `packages/core/src/api/index.ts`

```typescript
export const createAuthEndpoint = (path, options, handler) => {
  return createEndpoint(path, {
    ...options,
    use: [...(options?.use || []), ...middleware],
  }, async (ctx) => handler(ctx));
};
```

### Core Data Models

**User**: id, email, emailVerified, name, image, createdAt, updatedAt
**Session**: id, userId, token, expiresAt, ipAddress, userAgent
**Account**: id, userId, providerId, accountId, accessToken, refreshToken, password
**Verification**: id, identifier, value, expiresAt

---

## Session Management

### Cookie Security

**File:** `packages/better-auth/src/cookies/index.ts`

```typescript
const cookieAttributes = {
  httpOnly: true,        // Prevents XSS
  secure: true,          // HTTPS only
  sameSite: "lax",       // CSRF protection
  path: "/",
};

// Secure prefix enforcement
const secureCookiePrefix = secure ? "__Secure-" : "";
```

**Security Features:**
- HttpOnly: JavaScript cannot access cookies
- Secure: HTTPS-only in production
- SameSite=Lax: Blocks cross-site POST
- `__Secure-` prefix: Browser enforces HTTPS

### HMAC-Signed Cookies

```typescript
// Sign cookie
const signature = await createHMAC("SHA-256", "base64urlnopad")
  .sign(secret, `${cookieName}=${cookieValue}`);
const signedValue = `${cookieValue}.${signature}`;

// Verify cookie
const [value, sig] = cookie.split(".");
const expected = await createHMAC("SHA-256", "base64urlnopad")
  .sign(secret, `${cookieName}=${value}`);
if (sig !== expected) return null; // Tampered
```

### Session Refresh Strategy

**File:** `packages/better-auth/src/api/routes/session.ts`

```typescript
// Only refresh when past updateAge threshold
const sessionIsDueToBeUpdated =
  session.expiresAt.valueOf() - expiresIn * 1000 + updateAge * 1000;

if (sessionIsDueToBeUpdated <= Date.now()) {
  await updateSession(token, {
    expiresAt: new Date(Date.now() + expiresIn * 1000)
  });
}
```

**Performance**: Reduces DB writes by 99% (1000 requests = 1 update vs 1000 updates)

### Cookie Caching Strategies

**1. Compact (Default)** - Base64url + HMAC (~200-300 bytes)
**2. JWT** - Signed JWT with HS256 (~400-500 bytes)
**3. JWE** - Encrypted JWT with A256CBC-HS512 (~600-800 bytes)

```typescript
session: {
  cookieCache: {
    enabled: true,
    strategy: "compact", // "jwt" | "jwe"
    maxAge: 300, // 5 minutes
  }
}
```

### Cookie Chunking

Automatically splits cookies > 4KB into chunks:

```typescript
// Sets: cookie.0, cookie.1, cookie.2...
const CHUNK_SIZE = 3900;
for (let i = 0; i < numChunks; i++) {
  setCookie(`${name}.${i}`, data.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE));
}
```

### Configuration

```typescript
export const auth = betterAuth({
  session: {
    expiresIn: 60 * 60 * 24 * 7,    // 7 days
    updateAge: 60 * 60 * 24,        // 1 day refresh threshold
    cookieCache: {
      enabled: true,
      strategy: "compact",
      maxAge: 60 * 5,
    },
  },
  advanced: {
    useSecureCookies: process.env.NODE_ENV === "production",
    crossSubDomainCookies: {
      enabled: true,
      domain: ".example.com",
    },
  },
});
```

---

## Password Security

### Scrypt Hashing

**File:** `packages/better-auth/src/crypto/password.ts`

```typescript
import { scrypt } from "@noble/hashes/scrypt";

const config = {
  N: 16384,   // CPU/memory cost (2^14)
  r: 16,      // Block size
  p: 1,       // Parallelization
  dkLen: 64,  // 512-bit output
};

async hash(password: string): Promise<string> {
  const salt = getRandomValues(new Uint8Array(16));
  const normalized = password.normalize("NFKC");
  const key = scrypt(new TextEncoder().encode(normalized), salt, config);
  return `scrypt$${bytesToHex(salt)}$${bytesToHex(key)}`;
}
```

**Why Scrypt?**
- Memory-hard algorithm (resistant to GPU/ASIC attacks)
- Requires ~16MB RAM per hash
- Configurable cost parameters

### Constant-Time Comparison

```typescript
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i]; // XOR accumulates differences
  }
  return result === 0;
}
```

**Why?** Prevents timing attacks where attackers measure response times to guess passwords.

### Timing Attack Prevention

**File:** `packages/better-auth/src/api/routes/sign-in.ts`

```typescript
const user = await findUserByEmail(email);

if (!user) {
  // CRITICAL: Hash even for non-existent users
  await password.hash(password);
  throw new APIError("UNAUTHORIZED", {
    message: "Invalid email or password", // Generic message
  });
}
```

Without this: Attacker can detect user existence by timing (1ms vs 100ms).

### Password Validation

```typescript
const minPasswordLength = config.minPasswordLength || 8;
const maxPasswordLength = config.maxPasswordLength || 128;

if (password.length < minPasswordLength) {
  throw new APIError("BAD_REQUEST", { message: "Password too short" });
}
if (password.length > maxPasswordLength) {
  throw new APIError("BAD_REQUEST", { message: "Password too long" });
}
```

**Max length?** Prevents DoS attacks (1MB password = minutes to hash).

### Configuration

```typescript
emailAndPassword: {
  enabled: true,
  minPasswordLength: 12,
  maxPasswordLength: 128,
  requireEmailVerification: true,
  sendResetPassword: async ({ user, url }) => {
    await sendEmail(user.email, url);
  },
  resetPasswordTokenExpiresIn: 3600,
  revokeSessionsOnPasswordReset: true,
}
```

---

## CSRF Protection

### Multi-Layer Defense

1. **SameSite Cookies** - Primary defense
2. **Origin Validation** - Secondary defense
3. **Callback URL Validation** - Tertiary defense

### Attack Example

```html
<!-- evil-site.com -->
<form action="https://your-app.com/api/auth/transfer" method="POST">
  <input type="hidden" name="amount" value="10000" />
</form>
<script>document.forms[0].submit();</script>
```

If user logged into your-app.com → Browser sends cookies → Transfer executes!

### Layer 1: SameSite Cookies

```typescript
sameSite: "lax"
```

| Value | Cross-Site GET | Cross-Site POST | Protection |
|-------|----------------|-----------------|------------|
| none | ✅ | ✅ | ❌ |
| lax | ✅ | ❌ | ✅ |
| strict | ❌ | ❌ | ✅✅ |

**Why lax?** `strict` breaks legitimate flows (email links, bookmarks).

### Layer 2: Origin Validation

**File:** `packages/better-auth/src/api/middlewares/origin-check.ts`

```typescript
const originHeader = headers.get("origin") || headers.get("referer");

if (useCookies && !originHeader) {
  throw new APIError("FORBIDDEN", { message: "CSRF check failed" });
}

const originURL = new URL(originHeader);
const baseURL = new URL(ctx.baseURL);

if (originURL.origin !== baseURL.origin) {
  const isTrusted = trustedOrigins?.some(t => matchOrigin(originHeader, t));
  if (!isTrusted) throw new APIError("FORBIDDEN");
}
```

### Wildcard Origin Matching

```typescript
trustedOrigins: [
  "https://example.com",           // Exact match
  "https://*.example.com",         // Subdomain wildcard
  "https://app-*-team.vercel.app", // Preview deployments
  "exp://",                        // Expo mobile
  "capacitor://",                  // Capacitor mobile
]
```

### Layer 3: Path Traversal Prevention

```typescript
// Regex blocks: //, /\, /%2f, /%5c
const safePathRegex = /^\/(?!\/|\\|%2f|%5c)[\w\-.\+/@]*(?:\?[\w\-.\+/=&%@]*)?$/i;

if (!safePathRegex.test(callbackURL)) {
  throw new APIError("BAD_REQUEST", { message: "Invalid callback URL" });
}
```

---

## Rate Limiting

### Why It Matters

**Without rate limiting:**
- Brute force: 1 million password attempts/hour
- Credential stuffing: Test leaked passwords
- Account enumeration: Discover registered emails
- DoS: Overload server

### Implementation

**File:** `packages/better-auth/src/api/rate-limiter/index.ts`

```typescript
const clientIP = getClientIP(request);
const key = `${clientIP}:${path}`;

const data = await getRateLimitData(key);
const timeSinceLastRequest = Date.now() - data.lastRequest;

if (timeSinceLastRequest > window * 1000) {
  // Reset window
  saveRateLimit(key, { count: 1, lastRequest: Date.now() });
  return null;
}

if (data.count >= max) {
  return new Response("Too many requests", {
    status: 429,
    headers: { "Retry-After": retryAfter }
  });
}

saveRateLimit(key, { count: data.count + 1, lastRequest: Date.now() });
```

### Default Rules

```typescript
const rules = [
  {
    pathMatcher: (p) => p.startsWith("/sign-in") || p.startsWith("/sign-up"),
    window: 10,  // 10 seconds
    max: 3,      // 3 requests
  },
  {
    pathMatcher: (p) => p.startsWith("/verify-email"),
    window: 60,  // 1 minute
    max: 5,      // 5 requests
  },
];
```

### Storage Backends

**1. Database (Default)** - Works with existing DB
**2. Redis (Production)** - Fast, scalable, auto-expiration
**3. Memory (Dev only)** - Lost on restart, single-server only

```typescript
rateLimit: {
  enabled: true,
  storage: {
    async get(key) { return await redis.get(key); },
    async set(key, value) {
      await redis.set(key, JSON.stringify(value), { EX: value.window });
    },
  },
  customRules: [
    {
      pathMatcher: (p) => p === "/sign-in/email",
      window: 60 * 15, // 15 minutes
      max: 5,
    },
  ],
}
```

### IP Detection

```typescript
const headers = [
  "x-forwarded-for",    // Standard proxy
  "x-real-ip",          // Nginx
  "cf-connecting-ip",   // Cloudflare
];

for (const header of headers) {
  const value = request.headers.get(header);
  if (value) return value.split(",")[0].trim();
}
```

---

## OAuth & Social Authentication

### Security Concerns

- **Authorization code interception** - PKCE protection
- **CSRF on callback** - State parameter encryption
- **Account takeover** - Email verification required
- **Open redirect** - URL validation

### State Management

**File:** `packages/better-auth/src/oauth2/state.ts`

```typescript
// Generate state with PKCE
const state = generateRandomString(32);
const codeVerifier = generateRandomString(128);

const stateData = {
  callbackURL,
  codeVerifier,
  expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutes
};

// Encrypt entire state object
const encrypted = await symmetricEncrypt({
  key: secret,
  data: JSON.stringify(stateData),
});

// Store in signed cookie (double-submit pattern)
await setSignedCookie("better-auth.state", encrypted, secret);
```

**Why encrypt?** State travels through OAuth provider and back. Encryption prevents:
- Tampering with callback URLs
- Reading sensitive data
- Session fixation attacks

### PKCE Flow

**File:** `packages/better-auth/src/oauth2/state.ts`

```typescript
// Step 1: Generate code verifier
const codeVerifier = generateRandomString(128);
const codeChallenge = base64url(sha256(codeVerifier));

// Step 2: Send challenge to provider
const authURL = `${provider.authEndpoint}?` +
  `code_challenge=${codeChallenge}&` +
  `code_challenge_method=S256`;

// Step 3: Exchange code with verifier
const tokens = await provider.validateAuthorizationCode({
  code,
  codeVerifier, // Provider verifies this matches challenge
  redirectURI,
});
```

**Why PKCE?** Without it, intercepted authorization codes can be exchanged for tokens.

### Account Linking Security

**File:** `packages/better-auth/src/api/routes/callback.ts`

```typescript
if (link) {
  const trustedProviders = options.account?.accountLinking?.trustedProviders || [];
  const isTrusted = trustedProviders.includes(provider.id);

  // CRITICAL: Only link verified emails
  if (!isTrusted && !userInfo.emailVerified) {
    return redirectOnError({ error: "Email not verified" });
  }

  await linkAccount({
    userId: existingUser.id,
    providerId: provider.id,
    accountId: userInfo.id,
  });
}
```

**Attack without verification:**
1. Attacker creates GitHub account with victim@example.com (unverified)
2. Triggers account linking
3. Links attacker's GitHub to victim's account
4. Gains access!

### Supported Providers

Google, GitHub, Apple, Discord, Microsoft, Facebook, Twitter, Spotify, LinkedIn, Twitch, Auth0, Keycloak, Okta, Slack, LINE, HubSpot

### Configuration

```typescript
socialProviders: {
  github: {
    clientId: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
  },
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  },
},
account: {
  accountLinking: {
    trustedProviders: ["github", "google"], // Email-verified providers only
    enabled: true,
  },
},
```

---

## Email Verification

### JWT-Based Tokens

**File:** `packages/better-auth/src/api/routes/email-verification.ts`

```typescript
async function createEmailVerificationToken(
  secret: string,
  email: string,
  expiresIn: number = 3600 // 1 hour
) {
  return await new SignJWT({
    email: email.toLowerCase(),
  })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime(Math.floor(Date.now() / 1000) + expiresIn)
    .sign(new TextEncoder().encode(secret));
}
```

**Why JWT?**
- Stateless (no DB lookup)
- Self-expiring
- Tamper-proof (HMAC signature)
- Payload embedded (email inside token)

### Token Verification

```typescript
try {
  const jwt = await jwtVerify(token, secret, { algorithms: ["HS256"] });
  const { email } = jwt.payload;

  await updateUser(email, { emailVerified: true });
} catch (e) {
  if (e instanceof JWTExpired) {
    return redirectOnError({ error: "token_expired" });
  }
  return redirectOnError({ error: "invalid_token" });
}
```

### Preventing User Enumeration

```typescript
const user = await findUserByEmail(email);

if (!user) {
  // CRITICAL: Don't reveal user doesn't exist
  await createEmailVerificationToken(secret, email); // Generate anyway
  return { status: true }; // Return success
}

// Send email for real users
await sendVerificationEmail({ user, url, token });
return { status: true };
```

**Why?** Attackers can discover registered emails:
- Email exists: "Verification sent"
- Email doesn't exist: "User not found"

Always return success to prevent enumeration.

### Email Change Flow

```typescript
// Step 1: Verify current password
const isValid = await password.verify({ hash, password: oldPassword });

// Step 2: Check new email isn't taken
const existing = await findUserByEmail(newEmail);
if (existing) throw new APIError("Email already in use");

// Step 3: Send verification to NEW email
const token = await createToken(secret, currentEmail, newEmail);
await sendEmail(newEmail, `${baseURL}/verify-email?token=${token}`);

// Step 4: On verification, update email
await updateUser(userId, { email: newEmail, emailVerified: true });
```

### Configuration

```typescript
emailVerification: {
  sendOnSignUp: true,
  autoSignInAfterVerification: true,
  async sendVerificationEmail({ user, url, token }) {
    await sendEmail({
      to: user.email,
      subject: "Verify your email",
      html: `<a href="${url}">Verify Email</a>`,
    });
  },
  expiresIn: 3600, // 1 hour
},
emailAndPassword: {
  requireEmailVerification: true, // Don't allow unverified logins
},
```

---

## Two-Factor Authentication

### Methods Supported

**File:** `packages/better-auth/src/plugins/two-factor/index.ts`

1. **TOTP** - Authenticator apps (Google Authenticator, Authy)
2. **OTP via Email** - Codes sent to email
3. **Backup Codes** - Single-use recovery codes

### TOTP Implementation

```typescript
// Generate secret
const secret = generateRandomString(32);
const encryptedSecret = await symmetricEncrypt({ key: secret, data: secret });

await db.create({
  model: "twoFactor",
  data: { userId, secret: encryptedSecret },
});

// Generate QR code
const totpURI = `otpauth://totp/${appName}:${email}?secret=${secret}&issuer=${appName}`;
const qrCode = await generateQRCode(totpURI);

return { secret, qrCode };
```

**Why encrypt secrets?** Database breach = attackers restore TOTP in their app.

### TOTP Verification

```typescript
const decrypted = await symmetricDecrypt({ key: secret, data: encrypted });

// Check ±30 second window for clock skew
const window = 1;
for (let i = -window; i <= window; i++) {
  const timeStep = Math.floor(Date.now() / 1000 / 30) + i;
  const expected = generateTOTPCode(decrypted, timeStep);

  if (constantTimeEqual(code, expected)) return true;
}

return false;
```

### Backup Codes

```typescript
// Generate hashed backup codes
const codes = [];
for (let i = 0; i < 10; i++) {
  codes.push(generateRandomString(10));
}

const hashed = await Promise.all(
  codes.map(c => createHMAC("SHA-256", "hex").sign(secret, c))
);

await db.update({ userId, backupCodes: JSON.stringify(hashed) });
return codes; // Show to user once
```

**Why hash?** Like passwords, backup codes must be hashed (one-time use).

### Trusted Devices

```typescript
// Create HMAC of userId + session
const token = await createHMAC("SHA-256", "base64urlnopad")
  .sign(secret, `${userId}!${sessionToken}`);

// Store in signed cookie
await setSignedCookie("trust-device", `${token}!${sessionToken}`, secret, {
  maxAge: 60 * 60 * 24 * 30, // 30 days
});

// Verify device trust
const [token, sessionToken] = cookie.split("!");
const expected = await createHMAC("SHA-256", "base64urlnopad")
  .sign(secret, `${userId}!${sessionToken}`);

if (token === expected) {
  // Skip 2FA
}
```

### 2FA Flow

```typescript
// Hook after sign-in
hooks: {
  after: [{
    matcher: (ctx) => ctx.path === "/sign-in/email",
    handler: async (ctx) => {
      const twoFactor = await db.findOne({ userId });

      if (!twoFactor?.enabled) return; // No 2FA
      if (await isDeviceTrusted(ctx)) return; // Trusted device

      // Delete session (require 2FA before granting access)
      await deleteSession(session.token);

      // Redirect to 2FA page
      throw new APIError("FOUND", {
        headers: { Location: "/two-factor" },
      });
    },
  }],
}
```

### Configuration

```typescript
plugins: [
  twoFactor({
    issuer: "YourApp",
    totpWindow: 1, // ±30 seconds
    backupCodeOptions: {
      number: 10,
      length: 10,
    },
    otpOptions: {
      async sendOTP({ user, otp }) {
        await sendEmail(user.email, `Code: ${otp}`);
      },
      expiresIn: 300, // 5 minutes
      length: 6,
    },
    trustedDeviceOptions: {
      enabled: true,
      cookieMaxAge: 60 * 60 * 24 * 30,
    },
  }),
],
```

---

## Passkeys & WebAuthn

### Overview

**File:** `packages/passkey/src/index.ts`

Passkeys use WebAuthn for passwordless authentication via biometrics or hardware keys.

### Registration Flow

```typescript
// Step 1: Generate registration options
const options = await generateRegistrationOptions({
  rpName: "My App",
  rpID: "example.com",
  userID: user.id,
  userName: user.email,
  attestationType: "none",
  authenticatorSelection: {
    residentKey: "preferred",
    userVerification: "preferred",
  },
});

// Store challenge in signed cookie
await setSignedCookie("passkey-challenge", options.challenge, secret, {
  maxAge: 300, // 5 minutes
});

return options;
```

```typescript
// Step 2: Verify registration
const verification = await verifyRegistrationResponse({
  response: clientResponse,
  expectedChallenge: challenge,
  expectedOrigin: origin,
  expectedRPID: rpID,
});

if (verification.verified) {
  await db.create({
    model: "passkey",
    data: {
      userId,
      credentialID: verification.registrationInfo.credentialID,
      publicKey: verification.registrationInfo.credentialPublicKey,
      counter: verification.registrationInfo.counter,
      deviceType: verification.registrationInfo.credentialDeviceType,
    },
  });
}
```

### Authentication Flow

```typescript
// Step 1: Generate authentication options
const passkeys = await db.findMany({ userId });

const options = await generateAuthenticationOptions({
  rpID: "example.com",
  allowCredentials: passkeys.map(p => ({
    id: p.credentialID,
    type: "public-key",
  })),
});

// Step 2: Verify authentication
const passkey = await db.findOne({ credentialID });

const verification = await verifyAuthenticationResponse({
  response: clientResponse,
  expectedChallenge: challenge,
  expectedOrigin: origin,
  expectedRPID: rpID,
  authenticator: {
    credentialID: passkey.credentialID,
    credentialPublicKey: passkey.publicKey,
    counter: passkey.counter,
  },
});

if (verification.verified) {
  // Update counter (replay attack prevention)
  await db.update({ id: passkey.id, counter: verification.authenticationInfo.newCounter });

  // Create session
  const session = await createSession(passkey.userId);
  return { session, user };
}
```

### Security Features

- Challenge stored in signed cookie with 5-minute expiration
- Counter-based replay attack prevention
- Origin verification required
- User verification preferred
- Resident key support (preferred)

### Configuration

```typescript
plugins: [
  passkey({
    rpName: "My App",
    rpID: "example.com",
    origin: "https://example.com",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
  }),
],
```

---

## Magic Links

### Overview

**File:** `packages/better-auth/src/plugins/magic-link/index.ts`

Passwordless authentication via email link.

### Implementation

```typescript
// Step 1: Request magic link
const token = generateRandomString(32);
const hashedToken = await createHMAC("SHA-256", "hex").sign(secret, token);

await db.create({
  model: "verification",
  data: {
    identifier: `magic-link:${email}`,
    value: hashedToken,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
  },
});

await sendEmail(email, `${baseURL}/magic-link/verify?token=${token}`);
```

```typescript
// Step 2: Verify magic link
const hashedToken = await createHMAC("SHA-256", "hex").sign(secret, token);

const record = await db.findOne({
  identifier: `magic-link:${email}`,
  value: hashedToken,
});

if (!record || record.expiresAt < new Date()) {
  throw new APIError("Invalid or expired magic link");
}

// Create session
const session = await createSession(user.id);
await db.delete({ id: record.id }); // One-time use

return { session, user };
```

### Configuration

```typescript
plugins: [
  magicLink({
    expiresIn: 300, // 5 minutes
    disableSignUp: false,
    sendMagicLink: async ({ email, url, token }) {
      await sendEmail({
        to: email,
        subject: "Sign in to your account",
        html: `<a href="${url}">Click here to sign in</a>`,
      });
    },
  }),
],
```

---

## Organization & Multi-Tenancy

### Overview

**File:** `packages/better-auth/src/plugins/organization/index.ts`

Full RBAC system with roles, permissions, and team management.

### Data Models

**Organization**: name, slug, logo, createdAt, metadata
**Member**: organizationId, userId, role, createdAt
**Invitation**: organizationId, email, role, status, expiresAt, inviterId
**Team** (optional): name, organizationId, createdAt
**OrganizationRole** (dynamic): organizationId, role, permission, createdAt

### Key Endpoints

```
POST   /organization/create
POST   /organization/update
POST   /organization/delete
POST   /organization/set-active
GET    /organization/list
POST   /organization/invite-member
POST   /organization/accept-invitation
POST   /organization/remove-member
POST   /organization/update-member-role
POST   /organization/has-permission
```

### Default Roles

- **owner**: Full access, can delete organization
- **admin**: Administrative access, can invite/remove members
- **member**: Basic access

### Permission Check

```typescript
const hasPermission = await client.organization.hasPermission({
  permission: "user:create",
  organizationId: "org_123",
});

if (!hasPermission) {
  throw new Error("Insufficient permissions");
}
```

### Configuration

```typescript
plugins: [
  organization({
    allowUserToCreateOrganization: true,
    teams: {
      enabled: true,
    },
    dynamicAccessControl: {
      enabled: true,
    },
    roles: {
      custom: {
        permissions: ["read", "write"],
      },
    },
    sendInvitationEmail: async ({ email, organization, inviter }) => {
      await sendEmail(email, `${inviter.name} invited you to ${organization.name}`);
    },
  }),
],
```

---

## Single Sign-On (SSO/SAML)

### Overview

**File:** `packages/sso/src/index.ts`

Enterprise SSO supporting SAML and OIDC protocols.

### Data Model

```typescript
ssoProvider: {
  issuer: string,
  oidcConfig: string, // JSON
  samlConfig: string, // JSON
  userId: string,
  providerId: string (unique),
  organizationId: string,
  domain: string,
  domainVerified: boolean,
}
```

### Key Endpoints

```
GET    /sso/sp-metadata         # SAML metadata
POST   /sso/register-provider   # Register SSO provider
POST   /sso/sign-in             # Initiate SSO flow
POST   /sso/callback            # OIDC callback
POST   /sso/acs                 # SAML assertion consumer
POST   /sso/request-domain-verification
POST   /sso/verify-domain
```

### Domain Verification

```typescript
// Step 1: Request verification
const verificationCode = generateRandomString(32);
await db.create({
  model: "domainVerification",
  data: { domain, code: verificationCode, organizationId },
});

// User adds TXT record: _better-auth-verification=<code>

// Step 2: Verify domain
const records = await dns.resolveTxt(`_better-auth-verification.${domain}`);
if (records.includes(verificationCode)) {
  await db.update({ domain, domainVerified: true });
}
```

### Configuration

```typescript
plugins: [
  sso({
    domainVerification: {
      enabled: true,
    },
  }),
],
```

---

## Account Management

### File Paths

- `packages/better-auth/src/api/routes/account.ts`
- `packages/better-auth/src/api/routes/update-user.ts`

### Account Linking Endpoints

```
GET    /list-accounts          # List linked accounts
POST   /link-social            # Link OAuth account
POST   /unlink-account         # Unlink account
POST   /get-access-token       # Get/refresh OAuth token
```

### User Profile Endpoints

```
POST   /update-user            # Update name, image
POST   /change-password        # Requires current password
POST   /set-password           # For social-only accounts
POST   /delete-user            # Delete account
POST   /change-email           # Requires verification
```

### Account Linking Flow

```typescript
// Only link verified emails or trusted providers
const trustedProviders = ["google", "github"];
const isTrusted = trustedProviders.includes(provider.id);

if (!isTrusted && !userInfo.emailVerified) {
  throw new APIError("Email not verified by provider");
}

await db.create({
  model: "account",
  data: {
    userId: existingUser.id,
    providerId: provider.id,
    accountId: userInfo.id,
    accessToken: tokens.accessToken,
  },
});
```

### Delete Account Flow

```typescript
// Step 1: Request deletion
const token = await createJWT({ userId }, secret, 86400);
await sendEmail(user.email, `${baseURL}/delete-user/callback?token=${token}`);

// Step 2: Confirm deletion
const { userId } = await verifyJWT(token);

// Run before hooks
await options.deleteUser?.beforeDelete?.(user, request);

// Delete user (cascades to accounts, sessions)
await db.delete({ model: "user", where: { id: userId } });

// Run after hooks
await options.deleteUser?.afterDelete?.(user, request);
```

### Configuration

```typescript
user: {
  deleteUser: {
    enabled: true,
    sendDeleteAccountVerification: async ({ user, url }) => {
      await sendEmail(user.email, url);
    },
    deleteTokenExpiresIn: 86400,
    beforeDelete: async (user) => {
      // Clean up user data
    },
  },
  changeEmail: {
    enabled: true,
    updateEmailWithoutVerification: false,
  },
},
account: {
  accountLinking: {
    enabled: true,
    trustedProviders: ["google", "github"],
    allowUnlinkingAll: false,
  },
},
```

---

## Multiple Sessions

### Overview

**File:** `packages/better-auth/src/plugins/multi-session/index.ts`

Manage concurrent sessions across multiple devices.

### Implementation

```typescript
// Each session gets its own cookie
const cookies = [
  "better-auth.session_token",           // Active session
  "better-auth.session_token_multi-1",   // Device 1
  "better-auth.session_token_multi-2",   // Device 2
  "better-auth.session_token_multi-3",   // Device 3
];

// List all device sessions
const sessions = await db.findMany({
  model: "session",
  where: { userId },
});

return sessions.map(s => ({
  ...s,
  isCurrent: s.token === currentSessionToken,
}));
```

### Switch Active Session

```typescript
// Set specific session as active
const session = await db.findOne({ token });
await setSessionCookie(ctx, session.token);
```

### Configuration

```typescript
plugins: [
  multiSession({
    maximumSessions: 5, // Max concurrent sessions
  }),
],
```

---

## Bearer Token Authentication

### Overview

**File:** `packages/better-auth/src/plugins/bearer/index.ts`

Converts bearer tokens to session cookies for API authentication.

### Implementation

```typescript
// Before hook: Read Authorization header
const authHeader = request.headers.get("Authorization");
if (authHeader?.startsWith("Bearer ")) {
  const token = authHeader.substring(7);

  // Verify HMAC signature (if required)
  if (requireSignature) {
    const [value, sig] = token.split(".");
    const expected = await createHMAC("SHA-256", "base64urlnopad")
      .sign(secret, value);
    if (sig !== expected) throw new APIError("Invalid token");
  }

  // Convert to session cookie
  await setSessionCookie(ctx, token);
}

// After hook: Expose token in header
response.headers.set("set-auth-token", sessionToken);
response.headers.append("Access-Control-Expose-Headers", "set-auth-token");
```

### Configuration

```typescript
plugins: [
  bearer({
    requireSignature: false, // true to require pre-signed tokens
  }),
],
```

---

## API Key Authentication

### Overview

**File:** `packages/better-auth/src/plugins/api-key/index.ts`

Generate and manage API keys for programmatic access.

### Implementation

```typescript
// Create API key
const key = `pk_${generateRandomString(32)}`;
const hashedKey = await hash(key);

await db.create({
  model: "apiKey",
  data: {
    key: hashedKey,
    userId,
    expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
    metadata: { name: "Production API" },
  },
});

return { key }; // Show once
```

### Verification

```typescript
const hashedKey = await hash(key);
const apiKey = await db.findOne({ key: hashedKey });

if (!apiKey || apiKey.expiresAt < new Date()) {
  throw new APIError("Invalid API key");
}

// Update usage
await db.update({
  id: apiKey.id,
  lastUsed: new Date(),
  usageCount: apiKey.usageCount + 1,
});
```

### Configuration

```typescript
plugins: [
  apiKey({
    hashKeys: true,
    rateLimit: {
      window: 60,
      max: 100,
    },
  }),
],
```

---

## Anonymous Authentication

### Overview

**File:** `packages/better-auth/src/plugins/anonymous/index.ts`

Create temporary users without credentials.

### Implementation

```typescript
// Create anonymous user
const tempEmail = `temp-${userId}@${domain}.com`;

const user = await db.create({
  model: "user",
  data: {
    email: tempEmail,
    emailVerified: false,
    name: "Guest User",
    isAnonymous: true,
  },
});

const session = await createSession(user.id);
return { session, user };
```

### Account Linking

```typescript
// When user signs up properly
hooks: {
  after: [{
    matcher: (ctx) => ctx.path === "/sign-up/email",
    handler: async (ctx) => {
      if (session.user.isAnonymous) {
        // Migrate data
        await options.onLinkAccount?.({
          anonymousUser: session.user,
          newUser: ctx.returned.user,
        });

        // Delete anonymous account
        if (!options.disableDeleteAnonymousUser) {
          await db.delete({ id: session.user.id });
        }
      }
    },
  }],
},
```

### Configuration

```typescript
plugins: [
  anonymous({
    emailDomainName: "example.com",
    disableDeleteAnonymousUser: false,
    onLinkAccount: async ({ anonymousUser, newUser }) => {
      // Migrate anonymous user data to new account
      await migrateData(anonymousUser.id, newUser.id);
    },
  }),
],
```

---

## Email OTP

### Overview

**File:** `packages/better-auth/src/plugins/email-otp/index.ts`

Passwordless authentication via email OTP codes.

### Implementation

```typescript
// Generate OTP
const otp = Math.floor(100000 + Math.random() * 900000).toString();
const hashedOTP = await hash(otp);

await db.create({
  model: "verification",
  data: {
    identifier: `email-otp:${email}`,
    value: hashedOTP,
    expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    attempts: 0,
  },
});

await sendEmail(email, `Your code: ${otp}`);
```

### Verification

```typescript
const record = await db.findOne({ identifier: `email-otp:${email}` });

if (!record || record.expiresAt < new Date()) {
  throw new APIError("Invalid or expired OTP");
}

if (record.attempts >= 3) {
  throw new APIError("Too many attempts");
}

const isValid = await verify({ hash: record.value, password: otp });

if (!isValid) {
  await db.update({ id: record.id, attempts: record.attempts + 1 });
  throw new APIError("Invalid OTP");
}

await db.delete({ id: record.id });
```

### Configuration

```typescript
plugins: [
  emailOTP({
    expiresIn: 300, // 5 minutes
    length: 6,
    maxAttempts: 3,
    sendOTP: async ({ email, otp }) => {
      await sendEmail(email, `Code: ${otp}`);
    },
  }),
],
```

---

## Phone Number Authentication

### Overview

Phone-based OTP authentication via SMS.

### Implementation

Similar to Email OTP but sends via SMS:

```typescript
plugins: [
  phoneNumber({
    sendOTP: async ({ phoneNumber, otp }) => {
      await sendSMS(phoneNumber, `Your code: ${otp}`);
    },
    expiresIn: 300,
    length: 6,
  }),
],
```

---

## Plugin Architecture

### Plugin Interface

**File:** `packages/core/src/types/plugin.ts`

```typescript
interface BetterAuthPlugin {
  id: string;
  endpoints?: Record<string, Endpoint>;
  hooks?: {
    before?: Hook[];
    after?: Hook[];
  };
  schema?: DBSchema;
  rateLimit?: RateLimitRule[];
  init?: (ctx: AuthContext) => InitResult;
  options?: PluginOptions;
  $ERROR_CODES?: Record<string, string>;
}
```

### Example Plugin

```typescript
const customPlugin = {
  id: "custom",

  // Add endpoints
  endpoints: {
    myEndpoint: createAuthEndpoint("/custom/endpoint", {
      method: "POST",
      body: z.object({ data: z.string() }),
    }, async (ctx) => {
      return { success: true };
    }),
  },

  // Add database schema
  schema: {
    customTable: {
      fields: {
        id: { type: "string", required: true },
        data: { type: "string" },
      },
    },
  },

  // Add hooks
  hooks: {
    after: [{
      matcher: (ctx) => ctx.path === "/sign-in",
      handler: async (ctx) => {
        // Custom logic after sign-in
        console.log("User signed in:", ctx.returned.user);
      },
    }],
  },

  // Add rate limiting
  rateLimit: [{
    pathMatcher: (path) => path.startsWith("/custom/"),
    window: 60,
    max: 10,
  }],
};
```

### Hook System

```typescript
hooks: {
  before: [
    {
      matcher: (ctx) => ctx.path === "/sign-in/email",
      handler: async (ctx) => {
        // Runs before sign-in
        // Can modify ctx.body
      },
    },
  ],
  after: [
    {
      matcher: (ctx) => ctx.path === "/sign-in/email",
      handler: async (ctx) => {
        // Runs after sign-in
        // Access ctx.returned for endpoint result
      },
    },
  ],
}
```

---

## Client SDK

### Overview

**File:** `packages/better-auth/src/client/vanilla.ts`

Framework-agnostic client with adapters for React, Vue, Svelte, Solid.

### Basic Usage

```typescript
import { createAuthClient } from "better-auth/react";

const client = createAuthClient({
  baseURL: "http://localhost:3000",
  plugins: [passkeyClient(), organizationClient()],
});

export const { signIn, signUp, signOut, useSession } = client;
```

### React Hooks

```typescript
function MyComponent() {
  const session = useSession();

  if (session.isPending) return <div>Loading...</div>;
  if (!session.data) return <div>Not signed in</div>;

  return (
    <div>
      <p>Welcome, {session.data.user.name}</p>
      <button onClick={() => signOut()}>Sign Out</button>
    </div>
  );
}
```

### API Methods

```typescript
// Email/password
await signIn.email({ email, password });
await signUp.email({ email, password, name });

// Social
await signIn.social({ provider: "github" });

// Session
const session = await client.session();
await signOut();

// Plugins
await client.twoFactor.enable({ password });
await client.organization.create({ name });
```

### Reactive State

Uses `nanostores` for reactivity:

```typescript
// Subscribe to session changes
client.useSession.subscribe((session) => {
  console.log("Session changed:", session);
});

// Cross-tab synchronization via BroadcastChannel
// Auto-refresh on window focus
// Auto-refresh on network reconnect
```

---

## Framework Integration

### Next.js

**File:** `packages/better-auth/src/integrations/next-js.ts`

```typescript
// app/api/auth/[...all]/route.ts
import { auth } from "@/lib/auth";

export const { GET, POST } = auth.handler;
```

### SvelteKit

```typescript
// hooks.server.ts
import { auth } from "$lib/auth";

export const handle = auth.handler;
```

### Solid Start

```typescript
// routes/api/auth/[...all].ts
import { auth } from "~/lib/auth";

export const GET = auth.handler;
export const POST = auth.handler;
```

### TanStack Start

```typescript
// routes/api/auth/$.ts
import { auth } from "@/lib/auth";

export const Route = createAPIFileRoute("/api/auth/$")({
  GET: auth.handler,
  POST: auth.handler,
});
```

---

## Cryptographic Implementations

### Algorithms Used

**File:** `packages/better-auth/src/crypto/`

1. **Symmetric Encryption**: XChaCha20-Poly1305 (AEAD cipher)
2. **Password Hashing**: Scrypt (N=16384, r=16, p=1)
3. **JWT Signing**: HMAC-SHA256
4. **JWT Encryption**: A256CBC-HS512 with HKDF
5. **HMAC**: SHA-256 with base64url encoding
6. **Random Generation**: Cryptographically secure (crypto.getRandomValues)

### XChaCha20-Poly1305 Encryption

```typescript
import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { managedNonce } from "@noble/ciphers/webcrypto";

const key = sha256(new TextEncoder().encode(secret));
const cipher = managedNonce(xchacha20poly1305)(key);

const encrypted = cipher.encrypt(new TextEncoder().encode(data));
return base64url(encrypted);
```

### HKDF Key Derivation

```typescript
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

const derivedKey = hkdf(
  sha256,
  new TextEncoder().encode(secret),
  new TextEncoder().encode(salt),
  info,
  64 // 512 bits
);
```

### JWT Encryption (JWE)

```typescript
import { EncryptJWT } from "jose";

const encryptionSecret = hkdf(sha256, secret, salt, info, 64);

const jwe = await new EncryptJWT(payload)
  .setProtectedHeader({ alg: "dir", enc: "A256CBC-HS512" })
  .setIssuedAt()
  .setExpirationTime(expiresIn)
  .encrypt(encryptionSecret);
```

---

## Database Layer

### Adapter Interface

**File:** `packages/core/src/db/adapter/index.ts`

```typescript
interface Adapter {
  create<T>(data: { model: string; data: T }): Promise<T>;
  findOne<T>(query: { model: string; where: Where[] }): Promise<T | null>;
  findMany<T>(query: { model: string; where?: Where[] }): Promise<T[]>;
  update<T>(query: { model: string; where: Where[]; update: Partial<T> }): Promise<T>;
  delete(query: { model: string; where: Where[] }): Promise<void>;
  transaction?(callback: () => Promise<any>): Promise<any>;
}
```

### Supported Databases

- **Prisma**: ORM-based adapter
- **Drizzle**: Type-safe SQL adapter
- **Kysely**: Query builder adapter
- **MongoDB**: NoSQL adapter
- **Memory**: In-memory (testing)

### Schema Generation

**File:** `packages/better-auth/src/db/get-migration.ts`

```typescript
// Automatic migration generation
const migration = await generateMigration({
  database: "postgresql",
  schema: combinedSchema,
});

console.log(migration); // SQL migration script
```

### Type Mappings

```typescript
postgres: {
  string: "varchar",
  number: "integer",
  boolean: "boolean",
  date: "timestamptz",
  json: "jsonb",
}
```

---

## Error Handling

### Generic Error Messages

**File:** `packages/core/src/error/index.ts`

```typescript
export const BASE_ERROR_CODES = {
  INVALID_EMAIL_OR_PASSWORD: "Invalid email or password", // Not "invalid password"
  PASSWORD_TOO_SHORT: "Password must be at least 8 characters",
  INVALID_TOKEN: "Invalid or expired token", // Generic
  USER_NOT_FOUND: "Account not found", // But often hidden
};
```

**Why generic?** Never leak information:
- ❌ "Invalid password" → Reveals email exists
- ✅ "Invalid email or password" → Ambiguous

### XSS Prevention

**File:** `packages/better-auth/src/api/routes/error.ts`

```typescript
function sanitize(input: string): string {
  return input
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

const safeCode = /^[A-Za-z0-9_-]+$/.test(code) ? code : "UNKNOWN";

const html = `
  <h1>Error: ${sanitize(safeCode)}</h1>
  <p>${sanitize(message)}</p>
`;
```

### Production Error Handling

```typescript
onError(e) {
  // Log full details internally
  logger.error(e.message, { stack: e.stack, path: e.path });

  // Return generic error to client (NO stack trace)
  return new Response(
    JSON.stringify({ error: "Internal server error" }),
    { status: 500 }
  );
}
```

---

## Security Headers & CORS

### Cookie Security Attributes

```typescript
{
  httpOnly: true,        // JavaScript cannot access
  secure: true,          // HTTPS only
  sameSite: "lax",       // CSRF protection
  path: "/",
  domain: ".example.com" // Optional cross-subdomain
}
```

### Secure Cookie Prefix

```typescript
const prefix = secure ? "__Secure-" : "";
const cookieName = `${prefix}better-auth.session_token`;
```

**`__Secure-` prefix:** Browser enforces HTTPS requirement.

### CORS Headers

```typescript
// Bearer token plugin
response.headers.set("Access-Control-Expose-Headers", "set-auth-token");
```

### Origin Validation

Origin checking middleware validates `Origin` or `Referer` headers on all state-changing requests.

---

## Production Deployment

### Environment Variables

```bash
# Required
BETTER_AUTH_URL=https://example.com
BETTER_AUTH_SECRET=<256-bit random key>
DATABASE_URL=postgresql://...

# OAuth (optional)
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
GOOGLE_CLIENT_ID=...
GOOGLE_CLIENT_SECRET=...

# Email (optional)
SMTP_HOST=smtp.sendgrid.net
SMTP_USER=apikey
SMTP_PASS=...

# Redis (optional)
REDIS_URL=redis://localhost:6379
```

### Production Configuration

```typescript
export const auth = betterAuth({
  baseURL: process.env.BETTER_AUTH_URL,
  secret: process.env.BETTER_AUTH_SECRET,

  session: {
    expiresIn: 60 * 60 * 24 * 7,
    updateAge: 60 * 60 * 24,
    cookieCache: {
      enabled: true,
      strategy: "compact",
      maxAge: 300,
    },
  },

  emailAndPassword: {
    enabled: true,
    minPasswordLength: 12,
    requireEmailVerification: true,
  },

  rateLimit: {
    enabled: true,
    storage: redisStorage,
  },

  trustedOrigins: [
    process.env.APP_URL,
    "https://*.example.com",
  ].filter(Boolean),

  socialProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    },
  },

  plugins: [
    twoFactor(),
    organization(),
    passkey(),
  ],

  onAPIError: {
    onError: (error, ctx) => {
      Sentry.captureException(error);
    },
  },
});
```

### Deployment Checklist

- [ ] HTTPS enabled (no HTTP)
- [ ] Strong secret (256+ bit random key)
- [ ] Email verification required
- [ ] Rate limiting with Redis
- [ ] Password min length ≥12
- [ ] Session cookies: HttpOnly, Secure, SameSite
- [ ] CSRF protection: Origin validation + trusted origins
- [ ] OAuth: Only email-verified providers
- [ ] Error logging: Sentry/monitoring service
- [ ] Database: Encrypted connections
- [ ] 2FA available (optional)
- [ ] Regular backups
- [ ] Security headers configured
- [ ] Dependency updates automated

---

## Security Best Practices

### Defense in Depth

1. **Session Security**
   - HMAC-signed cookies
   - HttpOnly, Secure, SameSite attributes
   - Automatic expiration and refresh
   - Cookie chunking for large data

2. **Password Security**
   - Scrypt hashing (memory-hard)
   - Constant-time comparison
   - Timing attack prevention
   - Min/max length validation

3. **CSRF Protection**
   - SameSite=lax cookies
   - Origin header validation
   - Callback URL validation
   - Path traversal prevention

4. **Rate Limiting**
   - Per-IP + per-endpoint
   - Redis storage for scale
   - Automatic retry-after headers
   - Plugin-specific limits

5. **OAuth Security**
   - PKCE for code exchange
   - Encrypted state parameter
   - Email verification for linking
   - Origin validation

6. **Email Verification**
   - JWT-based stateless tokens
   - User enumeration prevention
   - Time-limited validity
   - Email change verification

7. **2FA Security**
   - Encrypted TOTP secrets
   - Hashed backup codes
   - Device trust with HMAC
   - Rate limiting

8. **Error Handling**
   - Generic error messages
   - XSS prevention via sanitization
   - Detailed internal logging
   - No information disclosure

### Common Vulnerabilities Prevented

✅ **SQL Injection**: Parameterized queries via adapters
✅ **XSS**: Output sanitization, HttpOnly cookies
✅ **CSRF**: SameSite cookies + origin validation
✅ **Session Fixation**: New session on login
✅ **Session Hijacking**: HMAC-signed cookies
✅ **Timing Attacks**: Constant-time comparison
✅ **Brute Force**: Rate limiting
✅ **Account Enumeration**: Consistent responses
✅ **Open Redirect**: URL validation
✅ **Clickjacking**: X-Frame-Options (via framework)
✅ **MITM**: HTTPS enforcement

### Security Headers (Recommended)

```typescript
// Add via middleware/framework
{
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'self'",
  "Referrer-Policy": "strict-origin-when-cross-origin",
}
```

### Monitoring & Alerting

```typescript
// Log security events
auth.onEvent({
  onSignIn: async ({ user, session }) => {
    await logEvent({
      type: "sign_in",
      userId: user.id,
      ip: session.ipAddress,
    });
  },

  onFailedSignIn: async ({ email, ip }) => {
    await logEvent({
      type: "failed_sign_in",
      email,
      ip,
    });

    // Alert on suspicious patterns
    if (await detectBruteForce(ip)) {
      await sendAlert({ severity: "high", message: `Brute force from ${ip}` });
    }
  },
});
```

### Regular Security Maintenance

1. **Dependency Updates**: Monthly security patches
2. **Secret Rotation**: Quarterly secret key rotation
3. **Access Review**: Quarterly review of API keys
4. **Log Analysis**: Weekly review of security logs
5. **Penetration Testing**: Annual security audit
6. **Incident Response**: Documented response plan

---

## Summary

Better-Auth is a comprehensive, production-ready authentication framework implementing industry-standard security practices across 20+ authentication methods. Key strengths:

### Architecture
- Framework-agnostic with adapters for all major frameworks
- Plugin-based extensibility with 20+ official plugins
- Type-safe with full TypeScript inference
- Database-agnostic with multiple adapter support

### Security
- Defense-in-depth: Multiple layers of protection
- Scrypt password hashing (memory-hard, GPU-resistant)
- HMAC-signed cookies with secure attributes
- CSRF protection via SameSite + origin validation
- Rate limiting with Redis support
- Constant-time comparisons preventing timing attacks
- PKCE for OAuth security
- JWT/JWE session caching
- XSS prevention via output sanitization
- Information disclosure prevention

### Authentication Methods
- Email/Password with verification
- OAuth (Google, GitHub, Apple, 15+ providers)
- Passkeys/WebAuthn
- Magic Links
- Two-Factor (TOTP, Email OTP, Backup codes)
- Anonymous authentication
- API Keys
- Bearer tokens
- Organization/Multi-tenancy with RBAC
- SSO/SAML for enterprise

### Developer Experience
- Simple configuration
- Automatic type inference
- Framework-specific adapters
- Comprehensive error handling
- Extensible plugin system
- Reactive client SDK
- Automatic database migrations

### Production Features
- Horizontal scalability (Redis rate limiting)
- Session caching strategies (JWE, JWT, Compact)
- Cookie chunking for large data
- Cross-tab synchronization
- Multiple concurrent sessions
- Automatic session refresh
- Monitoring and alerting hooks
- Comprehensive error logging

Better-Auth demonstrates enterprise-grade authentication with attention to security details while maintaining excellent developer experience through type safety and clear APIs.

---

**End of Report**

*For implementation details, see source code references throughout this document.*
