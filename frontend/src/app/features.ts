import { HttpClient } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { Observable, tap } from 'rxjs';

export interface FeatureRow {
  key: string;
  title: string;
  description: string;
  category: string;
  toggleable: boolean;
  planned: boolean;
  enabled: boolean;
  nav: { route: string; label: string; icon: string } | null;
  external: { label: string; url: string; note: string } | null;
}

/**
 * Shared feature state for the whole app: the sidebar and the Features page read the same signals, so a
 * toggle on the Features page shows up in the sidebar instantly (optimistic), then the POST confirms.
 */
@Injectable({ providedIn: 'root' })
export class FeaturesService {
  private http = inject(HttpClient);
  readonly rows = signal<FeatureRow[] | null>(null);
  // Enabled feature keys. null = not loaded yet (treat everything as visible, so the sidebar doesn't flash).
  readonly enabledKeys = signal<Set<string> | null>(null);

  refresh(): Observable<FeatureRow[]> {
    return this.http.get<FeatureRow[]>('/api/features').pipe(tap((f) => this.ingest(f)));
  }

  setEnabled(key: string, enabled: boolean): Observable<unknown> {
    this.applyLocal(key, enabled);                               // instant
    return this.http.post(`/api/features/${key}`, { enabled }).pipe(
      tap({
        next: () => this.refresh().subscribe(),                  // reconcile with the server
        error: () => this.applyLocal(key, !enabled),             // roll back on failure
      }),
    );
  }

  enabled(key: string): boolean {
    const e = this.enabledKeys();
    return e === null || e.has(key);
  }

  anyEnabled(keys: string[]): boolean {
    const e = this.enabledKeys();
    return e === null || keys.some((k) => e.has(k));
  }

  private ingest(rows: FeatureRow[]): void {
    this.rows.set(rows);
    this.enabledKeys.set(new Set(rows.filter((r) => r.enabled).map((r) => r.key)));
  }

  private applyLocal(key: string, enabled: boolean): void {
    const set = new Set(this.enabledKeys() ?? []);
    if (enabled) set.add(key);
    else set.delete(key);
    this.enabledKeys.set(set);
    const rows = this.rows();
    if (rows) this.rows.set(rows.map((r) => (r.key === key ? { ...r, enabled } : r)));
  }
}
