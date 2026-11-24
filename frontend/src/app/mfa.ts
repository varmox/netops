import { HttpClient } from '@angular/common/http';
import { Component, inject, input, output, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { ClarityModule } from '@clr/angular';
import { firstValueFrom } from 'rxjs';
import { Auth, LoginResult, errorText } from './auth';

/** Authenticator app: QR code (rendered server-side, trusted SVG), then the first code confirms it. */
@Component({
  selector: 'app-totp-enroll',
  imports: [ClarityModule, FormsModule],
  template: `
    @if (!qr()) {
      <button class="btn btn-primary" (click)="start()" [disabled]="busy()">Set up an authenticator app</button>
    } @else {
      <ol class="steps">
        <li>Scan this code with an authenticator app (1Password, Bitwarden, Google/Microsoft Authenticator…).</li>
      </ol>
      <div class="qr" [innerHTML]="qr()"></div>
      <p class="muted small">Can't scan? Enter this key: <span class="mono">{{ secret() }}</span></p>
      <form (ngSubmit)="confirm()" class="confirm">
        <clr-input-container>
          <label>Code from the app</label>
          <input clrInput name="code" [(ngModel)]="code" inputmode="numeric" autocomplete="one-time-code"
                 maxlength="7" required placeholder="123456" />
        </clr-input-container>
        <button type="submit" class="btn btn-primary" [disabled]="busy() || code.length < 6">Confirm</button>
      </form>
    }
    @if (error()) { <div class="alert-error">{{ error() }}</div> }
  `,
  styles: `
    .qr { width: 220px; margin: 0.5rem 0; background: #fff; padding: 6px; border-radius: 4px; }
    .qr ::ng-deep svg { width: 100%; height: auto; display: block; }
    .confirm { display: flex; align-items: flex-end; gap: 0.8rem; }
    .alert-error { color: #c92100; margin-top: 0.5rem; }
    .small { font-size: 0.75rem; word-break: break-all; }
    .steps { padding-left: 1.1rem; }
  `,
})
export class TotpEnroll {
  readonly done = output<LoginResult>();
  private http = inject(HttpClient);
  private sanitizer = inject(DomSanitizer);
  protected qr = signal<SafeHtml | null>(null);
  protected secret = signal('');
  protected code = '';
  protected busy = signal(false);
  protected error = signal<string | null>(null);

  protected async start(): Promise<void> {
    this.busy.set(true);
    try {
      const r = await firstValueFrom(this.http.post<{ secret: string; qr_svg: string }>('/api/auth/totp/setup', {}));
      this.secret.set(r.secret);
      this.qr.set(this.sanitizer.bypassSecurityTrustHtml(r.qr_svg));
    } catch (e) {
      this.error.set(errorText(e));
    }
    this.busy.set(false);
  }

  protected async confirm(): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    try {
      this.done.emit(await firstValueFrom(this.http.post<LoginResult>('/api/auth/totp/confirm', { code: this.code })));
    } catch (e) {
      this.error.set(errorText(e));
    }
    this.busy.set(false);
  }
}

@Component({
  selector: 'app-passkey-enroll',
  imports: [ClarityModule, FormsModule],
  template: `
    <form (ngSubmit)="register()" class="row">
      <clr-input-container>
        <label>Name for this passkey</label>
        <input clrInput name="pkname" [(ngModel)]="name" placeholder="MacBook Touch ID, YubiKey…" maxlength="40" />
      </clr-input-container>
      <button type="submit" class="btn btn-primary" [disabled]="busy()">Add a passkey</button>
    </form>
    @if (hostHint()) { <p class="muted small">Passkeys only work on <span class="mono">https://{{ hostHint() }}</span>.</p> }
    @if (error()) { <div class="alert-error">{{ error() }}</div> }
  `,
  styles: `
    .row { display: flex; align-items: flex-end; gap: 0.8rem; flex-wrap: wrap; }
    .alert-error { color: #c92100; margin-top: 0.5rem; }
    .small { font-size: 0.75rem; }
  `,
})
export class PasskeyEnroll {
  readonly hostHint = input<string>();
  readonly done = output<LoginResult>();
  private auth = inject(Auth);
  protected name = '';
  protected busy = signal(false);
  protected error = signal<string | null>(null);

  protected async register(): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    try {
      this.done.emit(await this.auth.passkeyRegister(this.name || 'Passkey'));
    } catch (e) {
      this.error.set(errorText(e));
    }
    this.busy.set(false);
  }
}

/** Shown exactly once: the user must confirm they saved the codes. */
@Component({
  selector: 'app-recovery-codes',
  imports: [ClarityModule, FormsModule],
  template: `
    <clr-alert clrAlertType="warning" [clrAlertClosable]="false">
      <clr-alert-item><span class="alert-text">Save these recovery codes now. Each works once if you lose your phone or
        passkey. They won't be shown again.</span></clr-alert-item>
    </clr-alert>
    <div class="codes mono">@for (c of codes(); track c) { <span>{{ c }}</span> }</div>
    <div class="btn-group">
      <button class="btn btn-sm btn-outline" (click)="copy()">{{ copied() ? 'Copied' : 'Copy' }}</button>
      <button class="btn btn-sm btn-outline" (click)="download()">Download .txt</button>
    </div>
    <clr-checkbox-wrapper>
      <input type="checkbox" clrCheckbox name="saved" [(ngModel)]="saved" />
      <label>I saved the recovery codes somewhere safe</label>
    </clr-checkbox-wrapper>
    <button class="btn btn-primary" [disabled]="!saved" (click)="done.emit()">Continue</button>
  `,
  styles: `
    .codes { display: grid; grid-template-columns: repeat(2, max-content); gap: 0.3rem 1.5rem; margin: 0.8rem 0; font-size: 0.95rem; }
    .btn-group { margin-bottom: 0.6rem; }
  `,
})
export class RecoveryCodes {
  readonly codes = input.required<string[]>();
  readonly done = output<void>();
  protected saved = false;
  protected copied = signal(false);

  protected async copy(): Promise<void> {
    await navigator.clipboard.writeText(this.codes().join('\n'));
    this.copied.set(true);
  }

  protected download(): void {
    const blob = new Blob(['NetOps recovery codes\n\n' + this.codes().join('\n') + '\n'], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'netops-recovery-codes.txt';
    a.click();
    URL.revokeObjectURL(a.href);
  }
}
