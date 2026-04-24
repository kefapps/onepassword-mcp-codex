import { appendFileSync } from "node:fs";

export interface AuditEvent {
  action: string;
  outcome: "success" | "error";
  metadata: Record<string, unknown>;
  errorMessage?: string;
}

export interface AuditLogger {
  record(event: AuditEvent): void;
}

export class FileAuditLogger implements AuditLogger {
  public constructor(private readonly logPath: string) {}

  public record(event: AuditEvent): void {
    const line = JSON.stringify({
      timestamp: new Date().toISOString(),
      pid: process.pid,
      ...event,
    });
    appendFileSync(this.logPath, `${line}\n`, "utf8");
  }
}

export class MemoryAuditLogger implements AuditLogger {
  public readonly events: AuditEvent[] = [];

  public record(event: AuditEvent): void {
    this.events.push(event);
  }
}
