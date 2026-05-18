export type StdioShutdownReason = "stdin_close" | "stdin_end";

export interface StdioLifecycleStream {
  once(event: "close" | "end", listener: () => void): unknown;
  off(event: "close" | "end", listener: () => void): unknown;
}

export function installStdioShutdownHandler(
  stdin: StdioLifecycleStream,
  shutdown: (reason: StdioShutdownReason) => void | Promise<void>,
): () => void {
  let triggered = false;

  const cleanup = () => {
    stdin.off("close", onClose);
    stdin.off("end", onEnd);
  };
  const trigger = (reason: StdioShutdownReason) => {
    if (triggered) {
      return;
    }
    triggered = true;
    cleanup();
    void shutdown(reason);
  };
  const onClose = () => {
    trigger("stdin_close");
  };
  const onEnd = () => {
    trigger("stdin_end");
  };

  stdin.once("close", onClose);
  stdin.once("end", onEnd);

  return cleanup;
}
