import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

export type Status = 'up' | 'degraded' | 'down' | 'unknown';

export interface CheckResult {
  check: string;
  ok: boolean;
  latency_ms: number | null;
  detail: string;
}

export interface DeviceState {
  status: Status;
  since: number | null;
  last_check: number | null;
  checks: CheckResult[];
  backup_ok: boolean | null;
  backup_last_run: number | null;
  backup_last_ok: number | null;
  backup_error: string | null;
  backup_running: boolean;
}

export interface BackupFile {
  name: string;
  size: number;
  text: boolean;
}

export interface BackupVersion {
  version: string;
  hash: string;
  files: BackupFile[];
  primary: string;
  previous: string | null;
  diffstat?: { added: number; removed: number };
}

export interface Device {
  id: string;
  name: string;
  type: string;
  host: string;
  role: string;
  notes: string;
  checks: { type: string; target?: string | number }[];
  backup: { method: string; binary?: boolean; redact?: boolean } | null;
  links: Record<string, string>;
  facts: Record<string, string>;
  state: DeviceState;
  latest_backup: { version: string; files: BackupFile[] } | null;
  protected: boolean;
  alert_on_down: boolean;
  alert_default: boolean;
  alert_overridden: boolean;
  managed: boolean;
}

/** The editable fields of a UI-managed device (POST /api/devices, PUT /api/devices/:id). */
export interface DeviceSpec {
  id: string;
  name: string;
  type: string;
  host: string;
  role: string;
  notes: string;
  checks: { type: string; target?: string | number }[];
  protected: boolean;
  alert: boolean | null;
  links?: Record<string, string>;
  facts?: Record<string, string>;
}

export interface Discovery {
  time: number | null;
  sources: string[];
  facts: Record<string, string>;
  vault_locked?: boolean;
}

export interface KioskLink { enabled: boolean; token: string | null; created: number | null; path: string | null }

export interface CredSlot { slot: string; name: string; set: boolean; referenced: boolean }
export interface DeviceCredentials {
  vault: { initialized: boolean; unlocked: boolean };
  managed: boolean;
  type: string;
  ssh_user: string | null;
  ssh_port: number | null;
  slots: CredSlot[];
}

export interface AlertPref {
  id: string;
  alert_on_down: boolean;
  alert_default: boolean;
  alert_overridden: boolean;
}

export interface Summary {
  devices: number;
  status: Record<Status, number>;
  backups: { devices: number; ok: number; failed: number };
  disk: { total: number; free: number };
  settings: { check_interval: number; backup_time: string; ntfy_topic: string };
}

export interface InboxFile {
  name: string;
  size: number;
  modified: string;
}

/** An ntfy message, as the backend relays it and as the live stream sends it. */
export interface Alert {
  id: string;
  time: number;
  title?: string;
  message: string;
  priority?: number;
  tags?: string[];
}

@Injectable({ providedIn: 'root' })
export class Api {
  private http = inject(HttpClient);

  summary(): Observable<Summary> {
    return this.http.get<Summary>('/api/summary');
  }
  devices(): Observable<Device[]> {
    return this.http.get<Device[]>('/api/devices');
  }
  device(id: string): Observable<Device> {
    return this.http.get<Device>(`/api/devices/${id}`);
  }
  checkNow(id: string): Observable<DeviceState> {
    return this.http.post<DeviceState>(`/api/devices/${id}/check`, {});
  }
  /** Set whether this device pages on down/degraded. `enabled: null` resets to the device default. */
  setAlert(id: string, enabled: boolean | null): Observable<AlertPref> {
    return this.http.post<AlertPref>(`/api/devices/${id}/alert`, { enabled });
  }
  /** Add a UI-managed device (stored in /data, not devices.yml). */
  createDevice(spec: DeviceSpec): Observable<Device> {
    return this.http.post<Device>('/api/devices', spec);
  }
  /** Update a UI-managed device. */
  updateDevice(id: string, spec: DeviceSpec): Observable<Device> {
    return this.http.put<Device>(`/api/devices/${id}`, spec);
  }
  /** Delete a UI-managed device. */
  deleteDevice(id: string): Observable<{ deleted: string }> {
    return this.http.delete<{ deleted: string }>(`/api/devices/${id}`);
  }
  /** Per-device vault-backed credentials (status only; values are never returned). */
  credentials(id: string): Observable<DeviceCredentials> {
    return this.http.get<DeviceCredentials>(`/api/devices/${id}/credentials`);
  }
  setCredential(id: string, body: { slot: string; value?: string; generate?: boolean; user?: string; port?: number }):
    Observable<{ ok: boolean; slot: string; set: boolean; public_key: string | null }> {
    return this.http.post<{ ok: boolean; slot: string; set: boolean; public_key: string | null }>(`/api/devices/${id}/credentials`, body);
  }
  clearCredential(id: string, slot: string): Observable<{ ok: boolean }> {
    return this.http.delete<{ ok: boolean }>(`/api/devices/${id}/credentials/${slot}`);
  }
  /** Kiosk / family-display share link (admin). */
  kiosk(): Observable<KioskLink> {
    return this.http.get<KioskLink>('/api/kiosk');
  }
  kioskRotate(): Observable<KioskLink> {
    return this.http.post<KioskLink>('/api/kiosk/rotate', {});
  }
  kioskDisable(): Observable<KioskLink> {
    return this.http.post<KioskLink>('/api/kiosk/disable', {});
  }
  /** Last hardware/firmware probe for a device. */
  discovery(id: string): Observable<Discovery> {
    return this.http.get<Discovery>(`/api/devices/${id}/discovery`);
  }
  /** Probe the device now (read-only: SSH, SNMP, then passive). */
  discover(id: string): Observable<Discovery> {
    return this.http.post<Discovery>(`/api/devices/${id}/discover`, {});
  }
  backups(id: string): Observable<BackupVersion[]> {
    return this.http.get<BackupVersion[]>(`/api/devices/${id}/backups`);
  }
  backupNow(id: string): Observable<{ version: string; changed: boolean }> {
    return this.http.post<{ version: string; changed: boolean }>(`/api/devices/${id}/backup`, {});
  }
  file(id: string, name: string): Observable<string> {
    return this.http.get(`/api/devices/${id}/files/${name}`, { responseType: 'text' });
  }
  fileUrl(id: string, name: string): string {
    return `/api/devices/${id}/files/${name}?download=true`;
  }
  diff(id: string, a: string, b: string): Observable<string> {
    return this.http.get(`/api/devices/${id}/diff`, { params: { a, b }, responseType: 'text' });
  }
  inbox(): Observable<InboxFile[]> {
    return this.http.get<InboxFile[]>('/api/inbox');
  }
  alerts(): Observable<Alert[]> {
    return this.http.get<Alert[]>('/api/alerts');
  }
  testAlert(): Observable<unknown> {
    return this.http.post('/api/alerts/test', {});
  }
  securitySummary(): Observable<SecuritySummary> {
    return this.http.get<SecuritySummary>('/api/security/summary');
  }
  findings(): Observable<Finding[]> {
    return this.http.get<Finding[]>('/api/security/findings');
  }
  findingAction(id: string, action: string): Observable<{ result: string }> {
    return this.http.post<{ result: string }>(`/api/security/findings/${encodeURIComponent(id)}/action`, { action });
  }
  securitySync(): Observable<{ started: boolean }> {
    return this.http.post<{ started: boolean }>('/api/security/sync', {});
  }
  securityScan(): Observable<{ started: boolean }> {
    return this.http.post<{ started: boolean }>('/api/security/scan', {});
  }
  securityServices(): Observable<{ time: number | null; targets: string[]; services: { host: string; port: number; proto: string; service: string; product: string }[] }> {
    return this.http.get<any>('/api/security/services');
  }
  securityNews(): Observable<{ title: string; link: string; date: string }[]> {
    return this.http.get<any>('/api/security/news');
  }
  quarantine(): Observable<{ kind: string; address: string; comment: string }[]> {
    return this.http.get<any>('/api/security/quarantine');
  }
  releaseQuarantine(kind: string, address: string): Observable<{ result: string }> {
    return this.http.post<{ result: string }>('/api/security/quarantine/release', { kind, address });
  }
  securityAudit(): Observable<{ time: number; action: string; by?: string; host?: string; result?: string; dry_run: boolean }[]> {
    return this.http.get<any>('/api/security/audit');
  }
  /** Several Prometheus queries in one round trip (backend runs them in parallel). */
  metrics(queries: Record<string, MetricQuery>): Observable<Record<string, MetricResult>> {
    return this.http.post<Record<string, MetricResult>>('/api/metrics/batch', { queries });
  }
}

export interface Proposal {
  action: string;
  label: string;
  description: string;
}

export interface Finding {
  id: string;
  cve: string;
  host: string;
  device: string | null;
  device_name: string;
  product: string;
  score: number | null;
  kev: boolean;
  severity: 'critical' | 'high' | 'medium' | 'low';
  summary: string;
  required_action: string | null;
  confidence: string;
  sources: string[];
  references: string[];
  status: 'open' | 'acknowledged' | 'remediating' | 'quarantined' | 'resolved';
  first_seen: number;
  last_seen: number;
  history: { time: number; action: string; by: string; result: string }[];
  proposals: Proposal[];
  /** Linux updates / Trivy: the individual packages or CVEs behind an aggregated finding. */
  items?: { id: string; pkg: string; installed: string; fixed: string; severity: string; title?: string; kev?: boolean }[];
}

export interface SecuritySummary {
  open: Record<'critical' | 'high' | 'medium' | 'low', number>;
  kev: number;
  quarantined: number;
  resolved: number;
  last_feeds: number | null;
  last_scan: number | null;
  running: Record<string, boolean>;
  dry_run: boolean;
}

export interface MetricQuery {
  q: string;
  minutes?: number;   // set: time series over the last N minutes; unset: current value
  points?: number;
}

export type MetricResult =
  | { labels: Record<string, string>; value: number }[]
  | { labels: Record<string, string>; values: [number, number][] }[]
  | { error: string };

/** "20261123T031500Z" -> Date */
export function versionDate(v: string): Date {
  return new Date(`${v.slice(0, 4)}-${v.slice(4, 6)}-${v.slice(6, 8)}T${v.slice(9, 11)}:${v.slice(11, 13)}:${v.slice(13, 15)}Z`);
}
