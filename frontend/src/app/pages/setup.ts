import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { firstValueFrom } from 'rxjs';
import { Auth, LoginResult, errorText } from '../auth';
import { PasskeyEnroll, RecoveryCodes, TotpEnroll } from '../mfa';

/** First run: the setup code from the host's log creates the first administrator. */
@Component({
  selector: 'app-setup',
  imports: [ClarityModule, FormsModule],
  template: `
    <div class="login-wrapper">
      <form class="login" (ngSubmit)="create()" #f="ngForm">
        <section class="title">
          <h3 class="welcome">Set up</h3>
          NetOps
          <h5 class="hint">Create the first administrator</h5>
        </section>
        <div class="login-group">
          <p class="muted small">The setup code is in the backend's log:<br />
            <span class="mono">docker compose logs backend | grep "SETUP CODE"</span></p>
          <clr-input-container>
            <label class="clr-sr-only">Setup code</label>
            <input clrInput name="code" [(ngModel)]="code" placeholder="Setup code (XXXX-XXXX-XXXX)" required autofocus autocomplete="off" />
          </clr-input-container>
          <clr-input-container>
            <label class="clr-sr-only">User name</label>
            <input clrInput name="username" [(ngModel)]="username" placeholder="User name" required autocomplete="username" />
          </clr-input-container>
          <clr-password-container>
            <label class="clr-sr-only">Password</label>
            <input clrPassword name="pw" [(ngModel)]="pw" placeholder="Password (at least 15 characters)" required autocomplete="new-password" />
          </clr-password-container>
          <clr-password-container>
            <label class="clr-sr-only">Repeat password</label>
            <input clrPassword name="pw2" [(ngModel)]="pw2" placeholder="Repeat password" required autocomplete="new-password" />
          </clr-password-container>
          <p class="muted small">Tip: a passphrase of 4–5 random words is long and easy to remember. It is checked against
            known breached passwords.</p>
          @if (error()) { <div class="error active">{{ error() }}</div> }
          <button type="submit" class="btn btn-primary" [disabled]="busy() || !f.valid">Create account</button>
        </div>
      </form>
    </div>
  `,
  styles: `
    .login-wrapper { background: linear-gradient(135deg, #0b1d33 0%, #12355b 55%, #0b1d33 100%); }
    .small { font-size: 0.75rem; }
  `,
})
export class SetupPage implements OnInit {
  private auth = inject(Auth);
  private router = inject(Router);
  protected code = '';
  protected username = '';
  protected pw = '';
  protected pw2 = '';
  protected busy = signal(false);
  protected error = signal<string | null>(null);

  ngOnInit(): void {
    this.auth.refresh().subscribe((s) => { if (!s.setup_required) this.router.navigateByUrl('/login'); });
  }

  protected async create(): Promise<void> {
    if (this.pw !== this.pw2) {
      this.error.set('The passwords are not the same.');
      return;
    }
    this.busy.set(true);
    this.error.set(null);
    try {
      await firstValueFrom(this.auth.setup(this.code, this.username, this.pw));
      this.router.navigateByUrl('/enroll');
    } catch (e) {
      this.error.set(errorText(e));
    }
    this.busy.set(false);
  }
}

/** Every account needs a second factor before it can do anything. */
@Component({
  selector: 'app-enroll',
  imports: [ClarityModule, TotpEnroll, PasskeyEnroll, RecoveryCodes],
  template: `
    <div class="wrap">
      <div class="card">
        <div class="card-header">Protect your account with a second factor</div>
        <div class="card-block">
          @if (codes(); as c) {
            <app-recovery-codes [codes]="c" (done)="finish()" />
          } @else {
            <p>NetOps can change your routers and firewalls, so every account needs a second factor. Choose one now;
              you can add more later under Account.</p>
            <clr-tabs>
              <clr-tab>
                <button clrTabLink>Passkey (recommended)</button>
                <clr-tab-content *clrIfActive="true">
                  <p class="muted">Touch ID, Face ID, Windows Hello, or a security key. Phishing-resistant, and it can
                    replace the password at login.</p>
                  <app-passkey-enroll [hostHint]="host()" (done)="enrolled($event)" />
                </clr-tab-content>
              </clr-tab>
              <clr-tab>
                <button clrTabLink>Authenticator app</button>
                <clr-tab-content *clrIfActive>
                  <app-totp-enroll (done)="enrolled($event)" />
                </clr-tab-content>
              </clr-tab>
            </clr-tabs>
          }
        </div>
      </div>
    </div>
  `,
  styles: `
    .wrap { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1rem;
      background: linear-gradient(135deg, #0b1d33 0%, #12355b 55%, #0b1d33 100%); }
    .card { max-width: 38rem; width: 100%; }
  `,
})
export class EnrollPage implements OnInit {
  private auth = inject(Auth);
  private router = inject(Router);
  protected codes = signal<string[] | null>(null);
  protected host = signal('');

  ngOnInit(): void {
    this.auth.refresh().subscribe((s) => {
      this.host.set(s.hostname);
      if (s.stage !== 'enroll' && s.stage !== 'full') this.router.navigateByUrl('/login');
    });
  }

  protected enrolled(r: LoginResult): void {
    if (r.recovery_codes?.length) this.codes.set(r.recovery_codes);
    else this.finish();
  }

  protected finish(): void {
    this.auth.refresh().subscribe(() => this.router.navigateByUrl('/dashboard'));
  }
}
