/**
 * The logger function is a TypeScript function that logs data to the console with an optional type
 * parameter.
 * @param {any} data - The `data` parameter is used to pass any type of data that you want to log. It
 * can be a string, number, object, array, or any other valid JavaScript data type.
 * @param {"log" | "error" | "warn"} [type=log] - The `type` parameter is a string that specifies the
 * type of log message. It can have one of three values: "log", "error", or "warn". The default value
 * is "log".
 */
export function logger(data: any, type: "log" | "error" | "warn" = "log") {
  console[type](data);
}
