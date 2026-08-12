import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process'

/**
 * Process helpers.
 *
 * Every call here uses argv arrays with `shell: false` (the default). No string
 * is ever handed to cmd.exe, so there is no command-injection surface even if a
 * value originates from the UI. Callers must still validate their arguments —
 * see security/validate.ts.
 */

export interface RunResult {
  code: number | null
  stdout: string
  stderr: string
  timedOut: boolean
}

export async function run(
  command: string,
  args: string[],
  opts: { timeoutMs?: number; maxOutputBytes?: number } = {}
): Promise<RunResult> {
  const timeoutMs = opts.timeoutMs ?? 15_000
  const maxOutput = opts.maxOutputBytes ?? 8 * 1024 * 1024

  return new Promise<RunResult>((resolve) => {
    let child: ChildProcessWithoutNullStreams
    try {
      child = spawn(command, args, { windowsHide: true, shell: false })
    } catch (err) {
      resolve({ code: -1, stdout: '', stderr: String(err), timedOut: false })
      return
    }

    let stdout = ''
    let stderr = ''
    let timedOut = false
    let settled = false

    const timer = setTimeout(() => {
      timedOut = true
      child.kill()
    }, timeoutMs)

    child.stdout.on('data', (chunk: Buffer) => {
      if (stdout.length < maxOutput) stdout += chunk.toString('utf8')
    })
    child.stderr.on('data', (chunk: Buffer) => {
      if (stderr.length < maxOutput) stderr += chunk.toString('utf8')
    })

    const finish = (code: number | null): void => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({ code, stdout, stderr, timedOut })
    }

    child.on('error', (err) => {
      stderr += String(err)
      finish(-1)
    })
    child.on('close', finish)
  })
}

/**
 * Runs a PowerShell snippet with no profile and no user-supplied interpolation.
 * The script is passed as a single argv element, never through a shell.
 */
export async function powershell(script: string, timeoutMs = 20_000): Promise<RunResult> {
  return run(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
    { timeoutMs }
  )
}

/** Parses JSON emitted by PowerShell, tolerating a single object or an array. */
export function parsePsJson<T>(stdout: string): T[] {
  const trimmed = stdout.trim()
  if (!trimmed) return []
  try {
    const parsed = JSON.parse(trimmed) as T | T[]
    return Array.isArray(parsed) ? parsed : [parsed]
  } catch {
    return []
  }
}
