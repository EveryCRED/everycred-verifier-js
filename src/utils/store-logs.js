export class StoreLogsService {
    logs = [];
    constructor() { }
    storeLogs(type, message) {
        const log = { type, message };
        this.logs.push(log);
    }
}
