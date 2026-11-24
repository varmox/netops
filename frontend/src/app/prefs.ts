import { Injectable, effect, signal } from '@angular/core';

export type ThemePref = 'system' | 'light' | 'dark';
export type Level = 'danger' | 'warning' | 'info' | 'success';

interface Stored {
  theme: ThemePref;
  autoRefresh: boolean;
  refreshSeconds: number;
  downBanner: boolean;
  desktopNotifications: boolean;
  levels: Level[];
}

const DEFAULTS: Stored = {
  theme: 'system',
  autoRefresh: true,
  refreshSeconds: 15,
  downBanner: true,
  desktopNotifications: false,
  levels: ['danger', 'warning', 'info', 'success'],
};
const KEY = 'netops-prefs';

/** Per-browser UI preferences (localStorage; the app works the same without it). */
@Injectable({ providedIn: 'root' })
export class Prefs {
  private readonly stored = load();
  readonly theme = signal<ThemePref>(this.stored.theme);
  readonly autoRefresh = signal(this.stored.autoRefresh);
  readonly refreshSeconds = signal(this.stored.refreshSeconds);
  readonly downBanner = signal(this.stored.downBanner);
  readonly desktopNotifications = signal(this.stored.desktopNotifications);
  readonly levels = signal<Level[]>(this.stored.levels);

  private readonly media = matchMedia('(prefers-color-scheme: dark)');

  constructor() {
    effect(() => {
      const value: Stored = {
        theme: this.theme(), autoRefresh: this.autoRefresh(), refreshSeconds: this.refreshSeconds(),
        downBanner: this.downBanner(), desktopNotifications: this.desktopNotifications(), levels: this.levels(),
      };
      try { localStorage.setItem(KEY, JSON.stringify(value)); } catch { /* private mode */ }
    });
    effect(() => this.applyTheme());
    this.media.addEventListener('change', () => this.applyTheme());
  }

  /** The theme actually shown ("system" resolved). */
  effectiveTheme(): 'light' | 'dark' {
    const t = this.theme();
    return t === 'system' ? (this.media.matches ? 'dark' : 'light') : t;
  }

  toggleLevel(level: Level, on: boolean): void {
    this.levels.update((l) => (on ? [...new Set([...l, level])] : l.filter((x) => x !== level)));
  }

  private applyTheme(): void {
    document.body.setAttribute('cds-theme', this.effectiveTheme());
  }
}

function load(): Stored {
  try {
    return { ...DEFAULTS, ...JSON.parse(localStorage.getItem(KEY) ?? '{}') };
  } catch {
    return { ...DEFAULTS };
  }
}
