import { HttpClient, HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { CanActivateFn, Router } from '@angular/router';
import { Observable, catchError, firstValueFrom, map, of, tap, throwError } from 'rxjs';

export type Stage = 'passkey' | 'mfa' | 'enroll' | 'full' | null;

export interface AuthState {
  setup_required: boolean;
  stage: Stage;
  hostname: string;
  user: { name: string; role: 'admin' | 'viewer'; factors: { totp: boolean; passkeys: number; recovery_codes: number } } | null;
}

export interface LoginResult {
  stage: Stage;
  methods?: ('totp' | 'passkey' | 'recovery')[];
  recovery_codes?: string[];
}

/**
 * Sessions live on the server (HttpOnly cookie). The app only mirrors the state:
 * setup -> (login -> mfa) | enroll -> full.
 */
@Injectable({ providedIn: 'root' })
export class Auth {
  private http = inject(HttpClient);
  private router = inject(Router);
  readonly state = signal<AuthState | null>(null);

  user() {
    const s = this.state();
    return s?.stage === 'full' ? s.user : null;
  }

  isAdmin(): boolean {
    return this.user()?.role === 'admin';
  }

  refresh(): Observable<AuthState> {
    return this.http.get<AuthState>('/api/auth/state').pipe(tap((s) => this.state.set(s)));
  }

  setup(code: string, username: string, password: string): Observable<LoginResult> {
    return this.http.post<LoginResult>('/api/auth/setup', { code, username, password });
  }

  login(username: string, password: string): Observable<LoginResult> {
    return this.http.post<LoginResult>('/api/auth/login', { username, password });
  }

  totp(code: string): Observable<LoginResult> {
    return this.http.post<LoginResult>('/api/auth/totp/verify', { code });
  }

  recovery(code: string): Observable<LoginResult> {
    return this.http.post<LoginResult>('/api/auth/recovery/verify', { code });
  }

  /** Passwordless, or as the second factor when a password session is waiting (stage mfa). */
  async passkeyLogin(): Promise<LoginResult> {
    assertWebAuthn();
    const options = await firstValueFrom(this.http.post<any>('/api/auth/passkey/login/options', {}));
    const cred = (await navigator.credentials.get({
      publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
    })) as PublicKeyCredential | null;
    if (!cred) throw new Error('No passkey was chosen.');
    return firstValueFrom(this.http.post<LoginResult>('/api/auth/passkey/login/verify', { credential: cred.toJSON() }));
  }

  async passkeyRegister(name: string): Promise<LoginResult> {
    assertWebAuthn();
    const options = await firstValueFrom(this.http.post<any>('/api/auth/passkey/register/options', {}));
    const cred = (await navigator.credentials.create({
      publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
    })) as PublicKeyCredential | null;
    if (!cred) throw new Error('No passkey was created.');
    return firstValueFrom(this.http.post<LoginResult>('/api/auth/passkey/register/verify', { credential: cred.toJSON(), name }));
  }

  logout(): void {
    this.http.post('/api/auth/logout', {}).subscribe({ complete: () => this.loggedOut(), error: () => this.loggedOut() });
  }

  loggedOut(next?: string): void {
    this.state.update((s) => (s ? { ...s, stage: null, user: null } : s));
    this.router.navigate(['/login'], next ? { queryParams: { next } } : {});
  }

  /** Where someone in this state belongs. */
  route(s: AuthState): string | null {
    if (s.setup_required) return '/setup';
    if (s.stage === 'enroll') return '/enroll';
    if (s.stage !== 'full') return '/login';
    return null;
  }
}

function assertWebAuthn(): void {
  if (!window.PublicKeyCredential || !('parseRequestOptionsFromJSON' in PublicKeyCredential)) {
    throw new Error('This browser does not support passkeys (needs Chrome 129+, Safari 18+, Firefox 119+).');
  }
}

export function errorText(e: unknown): string {
  if (e instanceof HttpErrorResponse) return e.error?.detail ?? e.message;
  if (e instanceof DOMException && e.name === 'NotAllowedError') return 'Cancelled, or the passkey prompt timed out.';
  return (e as Error)?.message ?? String(e);
}

export const authGuard: CanActivateFn = (_route, state) => {
  const auth = inject(Auth);
  const router = inject(Router);
  return auth.refresh().pipe(
    map((s) => {
      const target = auth.route(s);
      return target ? router.createUrlTree([target], target === '/login' ? { queryParams: { next: state.url } } : {}) : true;
    }),
    catchError(() => of(router.createUrlTree(['/login']))),
  );
};

/** CSRF: every request carries a header a cross-site form can't set. Session expired -> login. */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const auth = inject(Auth);
  const router = inject(Router);
  return next(req.clone({ setHeaders: { 'X-NetOps': '1' } })).pipe(catchError((err: HttpErrorResponse) => {
    if (err.status === 401 && !req.url.startsWith('/api/auth/')) {
      auth.loggedOut(router.url);
    }
    return throwError(() => err);
  }));
};
