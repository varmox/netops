import { HttpClient } from '@angular/common/http';
import { Component, OnInit, inject, signal } from '@angular/core';
import { ClarityModule } from '@clr/angular';

interface FamilyRow { name: string; role: string; status: string; kind: string; icon: string }
interface Family {
  ok: boolean;
  online: number;
  total: number;
  devices: FamilyRow[];
  warnings: { exposures: number; honeypot: number };
}

@Component({
  selector: 'app-family',
  imports: [ClarityModule],
  template: `
    @if (data(); as d) {
      <div class="hero" [class.good]="d.ok" [class.bad]="!d.ok">
        <cds-icon [shape]="d.ok ? 'check-circle' : 'exclamation-circle'" size="48"></cds-icon>
        <div>
          <h1>{{ d.ok ? 'Everything looks fine' : 'Needs a look' }}</h1>
          <p>{{ d.online }} of {{ d.total }} devices online.
            @if (d.warnings.exposures) { <span class="warn">· {{ d.warnings.exposures }} thing(s) reachable from the internet</span> }
            @if (d.warnings.honeypot) { <span class="warn">· {{ d.warnings.honeypot }} suspicious connection(s)</span> }
          </p>
        </div>
      </div>

      <div class="grid">
        @for (dev of d.devices; track dev.name) {
          <div class="tile" [class]="'s-' + dev.status">
            <cds-icon [shape]="dev.icon" size="28"></cds-icon>
            <div class="nm">{{ dev.name }}</div>
            <div class="rl">{{ dev.role }}</div>
            <span class="dot" [title]="dev.status"></span>
          </div>
        }
      </div>
    }
  `,
  styles: `
    /* Translucent tints so the hero and tiles read correctly in both light and dark themes. */
    .hero { display: flex; gap: 1rem; align-items: center; padding: 1.3rem 1.2rem; border-radius: 0.5rem; margin-bottom: 1.4rem; border: 1px solid transparent; }
    .hero.good { background: rgba(98, 164, 32, 0.12); border-color: rgba(98, 164, 32, 0.35); }
    .hero.good cds-icon { color: #62a420; }
    .hero.bad { background: rgba(230, 161, 0, 0.14); border-color: rgba(230, 161, 0, 0.4); }
    .hero.bad cds-icon { color: #e6a100; }
    .hero h1 { margin: 0 0 0.2rem; font-size: 1.4rem; }
    .hero p { margin: 0; opacity: 0.8; }
    .warn { color: #c77700; font-weight: 500; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); gap: 0.8rem; }
    .tile { position: relative; padding: 1rem 0.8rem; border-radius: 0.5rem; text-align: center; background: rgba(128, 128, 128, 0.06); border: 1px solid rgba(128, 128, 128, 0.18); }
    .tile .nm { font-weight: 600; margin-top: 0.4rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .tile .rl { font-size: 0.75rem; opacity: 0.65; }
    .dot { position: absolute; top: 0.6rem; right: 0.6rem; width: 0.6rem; height: 0.6rem; border-radius: 50%; background: #9aa5ad; }
    .s-up .dot { background: #62a420; }
    .s-down .dot { background: #e12200; }
    .s-degraded .dot { background: #e6a100; }
  `,
})
export class FamilyPage implements OnInit {
  private http = inject(HttpClient);
  protected data = signal<Family | null>(null);

  ngOnInit(): void {
    this.http.get<Family>('/api/family').subscribe((d) => this.data.set(d));
  }
}
