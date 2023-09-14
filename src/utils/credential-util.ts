import { cloneDeep, get, has, isEmpty } from "lodash";
import { logger } from "./logger";

/**
 * This function deep clones the input data using the cloneDeep method.
 * @param {any} data - The parameter "data" is of type "any", which means it can be any data type
 * (string, number, object, array, etc.). It is the data that needs to be cloned deeply.
 * @returns The function `deepCloneData` returns the result of calling the `cloneDeep` function on the
 * `data` parameter, if `data` is truthy. If `data` is falsy, the function does not return anything.
 */
export function deepCloneData(data: any): any {
  if (data) return cloneDeep(data);
}

/**
 * The function checks if a given key is present in a given object.
 * @param {any} data - The data parameter is of type "any", which means it can be any data type
 * (string, number, object, etc.). It is the data that we want to check for the presence of a key.
 * @param {string} key - The "key" parameter is a string that represents the name of the key that we
 * want to check for presence in the "data" object.
 * @returns The function `isKeyPresent` is returning a boolean value. It checks if both `data` and
 * `key` are truthy values, and if so, it calls the `has` function with `data` and `key` as arguments.
 * The `has` function is not shown in the code snippet, but it is likely a custom function that checks
 * if the `key` is present
 */
export function isKeyPresent(data: any, key: string): boolean {
  return data && key ? has(data, key) : false;
}

/**
 * This function retrieves data from a given key in an object, with an optional default value if the
 * key is not found.
 * @param {any} data - The data parameter is an object or array from which we want to retrieve a value
 * using a specific key.
 * @param {string} key - The key is a string that represents the path to the value that needs to be
 * retrieved from the data object. It can be a single key or a nested path of keys separated by dots.
 * @param {any} [defaultValue=null] - The defaultValue parameter is an optional parameter that
 * specifies the value to be returned if the key is not found in the data object. If this parameter is
 * not provided, the function will return null by default.
 * @returns The function `getDataFromKey` is returning the value of the property with the specified
 * `key` from the `data` object. If the property does not exist, it returns the `defaultValue`
 * parameter. The `get` function is being used to retrieve the value of the property.
 */
export function getDataFromKey(
  data: any,
  key: string | any[],
  defaultValue: any = null
) {
  return get(data, key, defaultValue);
}

/**
 * This function retrieves data from an API using a provided URL and logs any errors that occur.
 * @param {string} url - The `url` parameter is a string that represents the URL of the API endpoint
 * from which data is to be fetched.
 * @returns The function `getDataFromAPI` is returning a Promise that resolves to the JSON data fetched
 * from the specified URL. If there is an error during the fetch or parsing of the JSON data, the
 * function logs the error using a `logger` function and re-throws the error.
 */
export async function getDataFromAPI(url: string, options?: any): Promise<any> {
  try {
    const response = isEmpty(options) ? await fetch(url) : await fetch(url, options);
    return await response.json();
  } catch (err) {
    console.log("response >> ", err);
    logger(err, "error");
    throw err;
  }
}

/**
 * This TypeScript function checks if a given date string has already passed.
 * @param {string} dateString - A string representing a date in a format that can be parsed by the Date
 * constructor, such as "2022-01-01" or "January 1, 2022".
 * @returns A Promise that resolves to a boolean value indicating whether the date in the input string
 * is expired or not.
 */
export function isDateExpired(dateString: string): boolean {
  const currentDate = new Date();
  const dateToCheck = new Date(dateString);

  return currentDate > dateToCheck;
}

/**
 * The function checks if an object is empty.
 * @param {any} data - The `data` parameter is of type `any`, which means it can accept any data type.
 * @returns a boolean value, indicating whether the given object is empty or not.
 */
export function isObjectEmpty(data: any): boolean {
  return isEmpty(data);
}