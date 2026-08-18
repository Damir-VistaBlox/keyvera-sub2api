import { extractApiErrorMessage } from './apiError'

export function buildAuthErrorMessage(
  error: unknown,
  options: {
    fallback: string
  }
): string {
  return extractApiErrorMessage(error, options.fallback)
}
