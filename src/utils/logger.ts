import { StoreLogsService } from './store-logs';

const storeLogs = new StoreLogsService();

/**
 * The function "logger" logs data to the console with an optional type parameter.
 * @param {any} data - The data that needs to be logged. It can be of any data type.
 * @param {"log" | "error" | "warn"} [type=log] - The `type` parameter is a string literal type that
 * can only have one of three values: "log", "error", or "warn". It is used to determine which console
 * method to call when logging the `data` parameter. If no value is provided for `type`, it defaults to
 * "
 */
export function logger(data: any, type: "log" | "error" | "warn" = "log") {
  console[type](data);
  storeLogs.storeLogs(data, type);
}
