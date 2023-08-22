/**
 * The function `sleep` is an asynchronous function that pauses the execution for a specified number of
 * milliseconds.
 * @param {number} milliseconds - The `milliseconds` parameter is a number that represents the duration
 * in milliseconds for which the function should sleep or pause execution.
 * @returns a Promise that resolves to void.
 */
export async function sleep(milliseconds: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
};