import { API_URLS, DEFAULT_API_URL, EnvironmentApis } from '../constants/common';

// Constants for API URLs
export const MERKLE_TREE_VALIDATION_API_URL = defineApiUrl();

/**
 * The function `defineApiUrl` returns the appropriate API URL based on the current window origin.
 * @returns a string value, which is the API URL based on the current window origin.
 */
export function defineApiUrl(): string {
  const windowOrigin = window.origin as EnvironmentApis;

  return API_URLS.get(windowOrigin) ?? DEFAULT_API_URL;
}
