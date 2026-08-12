/**
 * Thin SQLite driver abstraction.
 *
 * Preferred backend is Node's built-in `node:sqlite` (Electron 43 ships Node 24,
 * where it is unflagged). If a future runtime drops it we transparently fall
 * back to `node-sqlite3-wasm`, which needs no native toolchain either.
 * Everything above this file talks to `SqliteDb` only.
 */

import { createRequire } from 'node:module'

export type SqlValue = string | number | bigint | Uint8Array | null
export type SqlRow = Record<string, SqlValue>

export interface SqliteStatement {
  run(params?: SqlValue[]): void
  get<T = SqlRow>(params?: SqlValue[]): T | undefined
  all<T = SqlRow>(params?: SqlValue[]): T[]
}

export interface SqliteDb {
  exec(sql: string): void
  prepare(sql: string): SqliteStatement
  transaction<T>(fn: () => T): T
  close(): void
  readonly driver: 'node:sqlite' | 'node-sqlite3-wasm'
}

const require_ = createRequire(import.meta.url)

interface NodeSqliteStatement {
  run(...params: SqlValue[]): unknown
  get(...params: SqlValue[]): unknown
  all(...params: SqlValue[]): unknown[]
}

function openNodeSqlite(path: string): SqliteDb | null {
  let DatabaseSync: new (p: string) => {
    exec(sql: string): void
    prepare(sql: string): NodeSqliteStatement
    close(): void
  }
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    ;({ DatabaseSync } = require_('node:sqlite'))
  } catch {
    return null
  }

  const db = new DatabaseSync(path)
  const wrap = (stmt: NodeSqliteStatement): SqliteStatement => ({
    run: (params = []) => void stmt.run(...params),
    get: <T,>(params: SqlValue[] = []) => stmt.get(...params) as T | undefined,
    all: <T,>(params: SqlValue[] = []) => stmt.all(...params) as T[]
  })

  return {
    driver: 'node:sqlite',
    exec: (sql) => db.exec(sql),
    prepare: (sql) => wrap(db.prepare(sql)),
    transaction<T>(fn: () => T): T {
      db.exec('BEGIN')
      try {
        const out = fn()
        db.exec('COMMIT')
        return out
      } catch (err) {
        db.exec('ROLLBACK')
        throw err
      }
    },
    close: () => db.close()
  }
}

interface WasmStatement {
  run(params?: SqlValue[]): unknown
  get(params?: SqlValue[]): unknown
  all(params?: SqlValue[]): unknown[]
  finalize(): void
}

function openWasmSqlite(path: string): SqliteDb {
  const { Database } = require_('node-sqlite3-wasm') as {
    Database: new (p: string) => {
      exec(sql: string): void
      prepare(sql: string): WasmStatement
      close(): void
    }
  }
  const db = new Database(path)
  const wrap = (stmt: WasmStatement): SqliteStatement => ({
    run: (params = []) => void stmt.run(params),
    get: <T,>(params: SqlValue[] = []) => stmt.get(params) as T | undefined,
    all: <T,>(params: SqlValue[] = []) => stmt.all(params) as T[]
  })

  return {
    driver: 'node-sqlite3-wasm',
    exec: (sql) => db.exec(sql),
    prepare: (sql) => wrap(db.prepare(sql)),
    transaction<T>(fn: () => T): T {
      db.exec('BEGIN')
      try {
        const out = fn()
        db.exec('COMMIT')
        return out
      } catch (err) {
        db.exec('ROLLBACK')
        throw err
      }
    },
    close: () => db.close()
  }
}

export function openDatabase(path: string): SqliteDb {
  const db = openNodeSqlite(path) ?? openWasmSqlite(path)
  db.exec('PRAGMA journal_mode = WAL;')
  db.exec('PRAGMA synchronous = NORMAL;')
  db.exec('PRAGMA foreign_keys = ON;')
  db.exec('PRAGMA busy_timeout = 5000;')
  return db
}
