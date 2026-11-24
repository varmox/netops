import { HttpClient } from '@angular/common/http';
import { Component, OnDestroy, OnInit, inject, input, signal } from '@angular/core';
import { ClarityModule } from '@clr/angular';

interface KDevice { name: string; role: string; status: string; icon: string }
interface KFamily { ok: boolean; online: number; total: number; devices: KDevice[] }

/** A login-free, auto-refreshing status display reached through a short share token (/k/<token>).
 * Renders full-screen (no app shell) for a wall display; serves only the safe status subset. */
@Component({
  selector: 'app-kiosk',
  imports: [ClarityModule],
  template: `
    <div class="kiosk" [class.good]="data()?.ok" [class.bad]="data() && !data()!.ok">
      @if (data(); as d) {
        <div class="hero">
          <cds-icon [shape]="d.ok ? 'check-circle' : 'exclamation-circle'" size="72"></cds-icon>
          <div>
            <h1>{{ d.ok ? 'All good' : 'Something is offline' }}</h1>
            <p>{{ d.online }} of {{ d.total }} devices online</p>
          </div>
          <div class="clock">{{ clock() }}</div>
        </div>
        <div class="grid">
          @for (dev of d.devices; track dev.name) {
            <div class="tile s-{{ dev.status }}">
              <cds-icon [shape]="dev.icon" size="40"></cds-icon>
              <div class="nm">{{ dev.name }}</div>
              <div class="rl">{{ dev.role }}</div>
              <span class="dot" [title]="dev.status"></span>
            </div>
          }
        </div>
      } @else if (invalid()) {
        <div class="center">
          <cds-icon shape="unknown-status" size="64"></cds-icon>
          <h1>This display link isn't valid</h1>
          <p>Ask an administrator to open it again from the Status page.</p>
        </div>
      } @else {
        <div class="center"><clr-progress-bar [clrLoop]="true"></clr-progress-bar></div>
      }
    </div>
  `,
  styles: `
    :host { display: block; }
    .kiosk { min-height: 100vh; box-sizing: border-box; padding: 4vh 4vw; background: var(--clr-global-app-background, #fafafa); }
    .kiosk.good { background: linear-gradient(180deg, rgba(98,164,32,0.10), transparent 40%); }
    .kiosk.bad { background: linear-gradient(180deg, rgba(225,34,0,0.12), transparent 40%); }
    .hero { display: flex; align-items: center; gap: 1.4rem; margin-bottom: 3vh; }
    .hero cds-icon { color: #9aa5ad; }
    .kiosk.good .hero cds-icon { color: #62a420; }
    .kiosk.bad .hero cds-icon { color: #e12200; }
    .hero h1 { margin: 0; font-size: clamp(1.8rem, 4vw, 3rem); }
    .hero p { margin: 0.2rem 0 0; font-size: clamp(1rem, 2vw, 1.4rem); opacity: 0.7; }
    .hero .clock { margin-left: auto; font-size: clamp(1.6rem, 4vw, 2.8rem); font-variant-numeric: tabular-nums; opacity: 0.6; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(clamp(150px, 16vw, 220px), 1fr)); gap: 1.2rem; }
    .tile { position: relative; padding: 1.6rem 1rem; border-radius: 0.7rem; text-align: center;
      background: rgba(128,128,128,0.08); border: 1px solid rgba(128,128,128,0.2); }
    .tile cds-icon { opacity: 0.85; }
    .tile .nm { font-weight: 600; font-size: clamp(1rem, 1.6vw, 1.3rem); margin-top: 0.5rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .tile .rl { font-size: clamp(0.72rem, 1.1vw, 0.9rem); opacity: 0.6; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .tile .dot { position: absolute; top: 0.8rem; right: 0.8rem; width: 0.8rem; height: 0.8rem; border-radius: 50%; background: #9aa5ad; }
    .s-up .dot { background: #62a420; }
    .s-down .dot { background: #e12200; }
    .s-degraded .dot { background: #e6a100; }
    .center { min-height: 80vh; display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.6rem; text-align: center; opacity: 0.75; }
    .center clr-progress-bar { width: 12rem; }
  `,
})
export class KioskPage implements OnInit, OnDestroy {
  readonly token = input.required<string>();
  private http = inject(HttpClient);
  protected data = signal<KFamily | null>(null);
  protected invalid = signal(false);
  protected clock = signal('');
  private timer?: ReturnType<typeof setInterval>;

  ngOnInit(): void {
    this.tick();
    this.load();
    this.timer = setInterval(() => { this.tick(); this.load(); }, 30000);
  }

  ngOnDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }

  private tick(): void {
    this.clock.set(new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
  }

  private load(): void {
    this.http.get<KFamily>(`/api/public/family/${this.token()}`).subscribe({
      next: (d) => { this.data.set(d); this.invalid.set(false); },
      error: () => { if (!this.data()) this.invalid.set(true); },
    });
  }
}
