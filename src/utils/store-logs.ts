export type logType = {
  type: "log" | "error" | "warn";
  message: string;
};

export class StoreLogsService {
  logs: logType[] = [];

  constructor() { }

  storeLogs(type: "log" | "error" | "warn", message: string) {
    const log = { type, message };
    this.logs.push(log);
  }
}