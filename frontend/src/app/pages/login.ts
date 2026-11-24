import { Component, OnInit, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { firstValueFrom } from 'rxjs';
import { Auth, LoginResult, errorText } from '../auth';

type Step = 'password' | 'mfa' | 'recovery';

/** Clarity's login layout (as vSphere): password, then a second factor; or a passkey alone. */
@Component({
  selector: 'app-login',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="login-wrapper">
      <div class="login">
        <section class="title">
          <h3 class="welcome">Welcome to</h3>
          NetOps
          <h5 class="hint">Home network operations</h5>
        </section>

        <div class="login-group">
          @switch (step()) {
            @case ('password') {
              <form (ngSubmit)="password()" #f="ngForm">
                <clr-input-container>
                  <label class="clr-sr-only">User name</label>
                  <input type="text" name="username" clrInput placeholder="User name" autocomplete="username webauthn"
                         [(ngModel)]="username" required autofocus />
                </clr-input-container>
                <clr-password-container>
                  <label class="clr-sr-only">Password</label>
                  <input type="password" name="password" clrPassword placeholder="Password" autocomplete="current-password"
                         [(ngModel)]="pw" required />
                </clr-password-container>
                @if (error()) { <div class="error active">{{ error() }}</div> }
                <button type="submit" class="btn btn-primary" [disabled]="busy() || !f.valid">Next</button>
              </form>
              <div class="or">or</div>
              <button type="button" class="btn btn-outline" (click)="passkey()" [disabled]="busy()">
                <cds-icon shape="key"></cds-icon> Sign in with a passkey
              </button>
            }
            @case ('mfa') {
              <p>Second step for <strong>{{ username }}</strong></p>
              @if (methods().includes('totp')) {
                <form (ngSubmit)="totp()">
                  <clr-input-container>
                    <label>Code from your authenticator app</label>
                    <input clrInput name="code" [(ngModel)]="code" inputmode="numeric" autocomplete="one-time-code"
                           maxlength="7" required autofocus placeholder="123456" />
                  </clr-input-container>
                  @if (error()) { <div class="error active">{{ error() }}</div> }
                  <button type="submit" class="btn btn-primary" [disabled]="busy() || code.length < 6">Log in</button>
                </form>
              } @else if (error()) { <div class="error active">{{ error() }}</div> }
              @if (methods().includes('passkey')) {
                <button type="button" class="btn btn-outline" (click)="passkey()" [disabled]="busy()">
                  <cds-icon shape="key"></cds-icon> Use a passkey
                </button>
              }
              @if (methods().includes('recovery')) {
                <button type="button" class="btn btn-link" (click)="step.set('recovery'); error.set(null)">Use a recovery code</button>
              }
              <button type="button" class="btn btn-link" (click)="reset()">Start over</button>
            }
            @case ('recovery') {
              <form (ngSubmit)="recovery()">
                <clr-input-container>
                  <label>Recovery code</label>
                  <input clrInput name="rc" [(ngModel)]="code" autocomplete="off" required autofocus placeholder="ABCD-EFGH-JKLM-NPQR" />
                </clr-input-container>
                @if (error()) { <div class="error active">{{ error() }}</div> }
                <button type="submit" class="btn btn-primary" [disabled]="busy() || !code">Log in</button>
              </form>
              <button type="button" class="btn btn-link" (click)="step.set('mfa'); error.set(null)">Back</button>
            }
          }
        </div>
        <div class="login-footer"><span class="muted">Protected by MFA · sessions end after inactivity</span></div>
      </div>
    </div>
  `,
  styles: `
    .login-wrapper {
      background:
        radial-gradient(circle at 70% 35%, rgba(0, 157, 219, 0.55), transparent 45%),
        radial-gradient(circle at 85% 80%, rgba(0, 194, 154, 0.35), transparent 40%),
        linear-gradient(135deg, #0b1d33 0%, #12355b 55%, #0b1d33 100%);
    }
    .or { text-align: center; margin: 0.6rem 0; opacity: 0.6; font-size: 0.8rem; }
  `,
})
export class LoginPage implements OnInit {
  readonly next = input<string>();
  private auth = inject(Auth);
  private router = inject(Router);
  protected step = signal<Step>('password');
  protected methods = signal<string[]>([]);
  protected username = '';
  protected pw = '';
  protected code = '';
  protected busy = signal(false);
  protected error = signal<string | null>(null);

  ngOnInit(): void {
    this.auth.refresh().subscribe((s) => {
      const target = this.auth.route(s);
      if (target === '/setup' || target === '/enroll') this.router.navigateByUrl(target);
      else if (!target) this.go();
    });
  }

  protected reset(): void {
    this.step.set('password');
    this.code = this.pw = '';
    this.error.set(null);
  }

  private async run(fn: () => Promise<LoginResult>): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    try {
      this.handle(await fn());
    } catch (e) {
      this.error.set(errorText(e));
      this.code = '';
    }
    this.busy.set(false);
  }

  private handle(r: LoginResult): void {
    if (r.stage === 'mfa') {
      this.methods.set(r.methods ?? []);
      this.step.set('mfa');
      this.pw = '';
    } else if (r.stage === 'enroll') {
      this.router.navigateByUrl('/enroll');
    } else if (r.stage === 'full') {
      this.go();
    }
  }

  private go(): void {
    this.auth.refresh().subscribe(() => {
      const next = this.next();
      if (next?.startsWith('/grafana/')) window.location.assign(next);
      else this.router.navigateByUrl(next?.startsWith('/') && !next.startsWith('//') ? next : '/dashboard');
    });
  }

  protected password(): void {
    this.run(() => firstValueFrom(this.auth.login(this.username, this.pw)));
  }

  protected totp(): void {
    this.run(() => firstValueFrom(this.auth.totp(this.code)));
  }

  protected recovery(): void {
    this.run(() => firstValueFrom(this.auth.recovery(this.code)));
  }

  protected passkey(): void {
    this.run(() => this.auth.passkeyLogin());
  }
}
