const API_ROOT = '/api'
const API_TIMEOUT_MS = 15000

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers)
  if (!(init?.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  const controller = new AbortController()
  let timedOut = false
  const timeout = window.setTimeout(() => {
    timedOut = true
    controller.abort()
  }, API_TIMEOUT_MS)
  const abortFromCaller = () => controller.abort()
  init?.signal?.addEventListener('abort', abortFromCaller, { once: true })

  try {
    const retryable = !init?.method || init.method.toUpperCase() === 'GET'
    for (let attempt = 0; attempt < (retryable ? 2 : 1); attempt += 1) {
      try {
        const response = await fetch(`${API_ROOT}${path}`, { ...init, headers, signal: controller.signal })
        if (response.status === 204) return undefined as T
        const body = await response.json().catch((error) => {
          if (controller.signal.aborted) throw error
          return {}
        })
        if (!response.ok) throw new Error(body.detail || 'Local API request failed')
        return body as T
      } catch (error) {
        if (controller.signal.aborted || attempt > 0 || !retryable) throw error
        await new Promise((resolve) => window.setTimeout(resolve, 250))
      }
    }
    throw new Error(`Local API request failed: ${path}`)
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') {
      if (timedOut) throw new Error(`Local API request timed out (${Math.round(API_TIMEOUT_MS / 1000)} seconds): ${path}`)
      throw new Error(`Local API request cancelled: ${path}`)
    }
    throw error
  } finally {
    window.clearTimeout(timeout)
    init?.signal?.removeEventListener('abort', abortFromCaller)
  }
}
