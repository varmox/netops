import { Component, OnInit, computed, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ClarityModule } from '@clr/angular';
import { firstValueFrom } from 'rxjs';
import { errorText } from '../auth';
import { FeatureRow as Feature, FeaturesService } from '../features';

const CATEGORIES: { key: string; label: string }[] = [
  { key: 'core', label: 'Core' },
  { key: 'watch', label: 'Watchers' },
  { key: 'active', label: 'Active defence' },
  { key: 'view', label: 'Views & reports' },
  { key: 'planned', label: 'Planned' },
];

@Component({
  selector: 'app-features',
  imports: [ClarityModule, RouterLink],
  template: `
    <div class="page-head"><h2>Features</h2></div>
    <p class="muted">Everything NetOps does, in one place — switch each on or off. Changes take effect
      immediately; nothing runs when it's off. Where a feature ships its own prebuilt UI, it's linked here
      rather than living on a separate page.</p>
    @if (msg(); as m) { <clr-alert [clrAlertType]="m.t" [clrAlertClosable]="true" (clrAlertClosedChange)="msg.set(null)"><clr-alert-item><span class="alert-text">{{ m.x }}</span></clr-alert-item></clr-alert> }

    @for (cat of categories(); track cat.key) {
      @if (byCat(cat.key).length) {
        <h3>{{ cat.label }}</h3>
        <div class="clr-row">
          @for (f of byCat(cat.key); track f.key) {
            <div class="clr-col-12 clr-col-md-6 clr-col-xl-4">
              <div class="card feat" [class.off]="!f.enabled && !f.planned">
                <div class="card-block">
                  <div class="feat-top">
                    <div class="feat-title">
                      @if (f.nav) { <cds-icon [shape]="f.nav.icon" size="18"></cds-icon> }
                      <span>{{ f.title }}</span>
                    </div>
                    @if (f.planned) {
                      <span class="label">planned</span>
                    } @else {
                      <clr-toggle-wrapper>
                        <input type="checkbox" clrToggle [checked]="f.enabled" [disabled]="!f.toggleable || busy() === f.key"
                               (change)="toggle(f)" [attr.aria-label]="'Enable ' + f.title" />
                      </clr-toggle-wrapper>
                    }
                  </div>
                  <p class="feat-desc">{{ f.description }}</p>
                  <div class="feat-links">
                    @if (f.nav && f.enabled) { <a class="btn btn-sm btn-link" [routerLink]="f.nav.route">Open {{ f.nav.label }}</a> }
                    @if (f.external) {
                      <a class="btn btn-sm btn-link" [href]="externalUrl(f)" target="_blank" rel="noopener">
                        {{ f.external.label }} <cds-icon shape="pop-out" size="12"></cds-icon></a>
                      <span class="muted ext-note">{{ f.external.note }}</span>
                    }
                    @if (!f.toggleable && !f.planned) { <span class="muted">always on</span> }
                  </div>
                </div>
              </div>
            </div>
          }
        </div>
      }
    }
  `,
  styles: `
    h3 { margin: 1.2rem 0 0.4rem; }
    .feat { height: calc(100% - 1rem); }
    .feat.off { opacity: 0.6; }
    .feat-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 0.5rem; }
    .feat-title { display: flex; align-items: center; gap: 0.4rem; font-weight: 600; }
    .feat-desc { color: var(--clr-color-neutral-700, #555); font-size: 0.85rem; margin: 0.4rem 0 0.6rem; }
    .feat-links { display: flex; align-items: center; gap: 0.3rem; flex-wrap: wrap; }
    .feat-links .btn { margin: 0; }
    .ext-note { font-size: 0.72rem; }
  `,
})
export class FeaturesPage implements OnInit {
  private svc = inject(FeaturesService);
  protected busy = signal<string | null>(null);
  protected msg = signal<{ t: 'success' | 'danger'; x: string } | null>(null);
  protected categories = computed(() => CATEGORIES);
  // Reads the shared signal, so toggles here are reflected here and in the sidebar at once.
  protected features = computed(() => this.svc.rows() ?? []);

  ngOnInit(): void {
    this.svc.refresh().subscribe();
  }

  protected byCat(cat: string): Feature[] {
    return this.features().filter((f) => f.category === cat);
  }

  protected externalUrl(f: Feature): string {
    if (f.external?.url) return f.external.url;
    // AdGuard admin UI ships on :3000 of this host when no explicit URL is configured.
    return `${location.protocol}//${location.hostname}:3000`;
  }

  protected async toggle(f: Feature): Promise<void> {
    this.busy.set(f.key);
    const target = !f.enabled;
    try {
      await firstValueFrom(this.svc.setEnabled(f.key, target));   // optimistic: sidebar updates instantly
      this.msg.set({ t: 'success', x: `${f.title} ${target ? 'enabled' : 'disabled'}.` });
    } catch (e) {
      this.msg.set({ t: 'danger', x: errorText(e) });
    }
    this.busy.set(null);
  }
}
