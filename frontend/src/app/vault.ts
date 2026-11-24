import { HttpClient } from '@angular/common/http';
import { Injectable, inject, signal } from '@angular/core';
import { Observable, tap } from 'rxjs';

export interface VaultStatus {
  initialized: boolean;
  unlocked: boolean;
  secrets: number;
  unlocked_at: number | null;
}

/** Vault state for the whole app (the shell shows a banner while it is locked). */
@Injectable({ providedIn: 'root' })
export class VaultService {
  private http = inject(HttpClient);
  readonly status = signal<VaultStatus | null>(null);

  refresh(): Observable<VaultStatus> {
    return this.http.get<VaultStatus>('/api/vault/status').pipe(tap((s) => this.status.set(s)));
  }

  unlock(passphrase: string): Observable<unknown> {
    return this.http.post('/api/vault/unlock', { passphrase }).pipe(tap(() => this.refresh().subscribe()));
  }
}
