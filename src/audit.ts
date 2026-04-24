import { constants, openSync, writeSync } from "node:fs";

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
  private readonly fileDescriptor: number;

  public constructor(private readonly logPath: string) {
    const noFollow = constants.O_NOFOLLOW ?? 0;
    this.fileDescriptor = openSync(
      this.logPath,
      constants.O_APPEND | constants.O_CREAT | constants.O_WRONLY | noFollow,
      0o600,
    );
  }

  public record(event: AuditEvent): void {
    const line = JSON.stringify({
      timestamp: new Date().toISOString(),
      pid: process.pid,
      ...event,
    });
    writeSync(this.fileDescriptor, `${line}\n`, undefined, "utf8");
  }
}

export class MemoryAuditLogger implements AuditLogger {
  public readonly events: AuditEvent[] = [];

  public record(event: AuditEvent): void {
    this.events.push(event);
  }
}
