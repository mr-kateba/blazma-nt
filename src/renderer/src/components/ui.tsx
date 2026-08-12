import { useMemo, useState, type ReactNode } from 'react'
import type { EncryptionStatus, TimeRange } from '@shared/types'
import { useApp } from '../state'
import type { TranslationKey } from '../i18n'

/* ------------------------------------------------------------------ */
/* Primitives                                                          */
/* ------------------------------------------------------------------ */

export function Card({
  title,
  action,
  children,
  className = ''
}: {
  title?: ReactNode
  action?: ReactNode
  children: ReactNode
  className?: string
}): React.JSX.Element {
  return (
    <section
      className={`rounded-xl border border-line bg-panel shadow-[0_1px_2px_rgba(0,0,0,0.18)] ${className}`}
    >
      {(title || action) && (
        <header className="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
          <h2 className="text-sm font-semibold text-ink">{title}</h2>
          {action}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  )
}

export function StatCard({
  label,
  value,
  hint,
  tone = 'neutral'
}: {
  label: string
  value: ReactNode
  hint?: ReactNode
  tone?: 'neutral' | 'ok' | 'warn' | 'danger' | 'accent'
}): React.JSX.Element {
  const toneColor = {
    neutral: 'text-ink',
    ok: 'text-ok',
    warn: 'text-warn',
    danger: 'text-danger',
    accent: 'text-accent'
  }[tone]
  return (
    <div className="rounded-xl border border-line bg-panel px-4 py-3">
      <div className="text-[11px] font-medium uppercase tracking-wide text-faint">{label}</div>
      <div className={`tnum mt-1 text-2xl font-semibold ${toneColor}`}>{value}</div>
      {hint && <div className="mt-0.5 text-xs text-muted">{hint}</div>}
    </div>
  )
}

export function Badge({
  children,
  tone = 'neutral',
  title
}: {
  children: ReactNode
  tone?: 'neutral' | 'ok' | 'warn' | 'danger' | 'accent' | 'violet'
  title?: string
}): React.JSX.Element {
  const styles: Record<string, string> = {
    neutral: 'bg-panel-hover text-muted border-line',
    ok: 'bg-ok-soft text-ok border-transparent',
    warn: 'bg-warn-soft text-warn border-transparent',
    danger: 'bg-danger-soft text-danger border-transparent',
    accent: 'bg-accent-soft text-accent border-transparent',
    violet: 'bg-panel-hover text-violet border-line'
  }
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap ${styles[tone]}`}
    >
      {children}
    </span>
  )
}

export function EncryptionBadge({ value }: { value: EncryptionStatus }): React.JSX.Element {
  const { t } = useApp()
  if (value === 'encrypted') return <Badge tone="ok">{t('value.encrypted')}</Badge>
  if (value === 'unencrypted') return <Badge tone="danger">{t('value.unencrypted')}</Badge>
  return <Badge tone="neutral">{t('value.unknown')}</Badge>
}

export function Button({
  children,
  onClick,
  variant = 'default',
  disabled,
  type = 'button',
  title
}: {
  children: ReactNode
  onClick?: () => void
  variant?: 'default' | 'primary' | 'danger' | 'ghost'
  disabled?: boolean
  type?: 'button' | 'submit'
  title?: string
}): React.JSX.Element {
  const styles: Record<string, string> = {
    default: 'border-line bg-panel-hover text-ink hover:border-line-strong',
    primary: 'border-transparent bg-accent text-[#04121c] hover:brightness-110 font-semibold',
    danger: 'border-transparent bg-danger text-white hover:brightness-110 font-semibold',
    ghost: 'border-transparent bg-transparent text-muted hover:text-ink hover:bg-panel-hover'
  }
  return (
    <button
      type={type}
      title={title}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-[13px] transition-colors disabled:cursor-not-allowed disabled:opacity-45 ${styles[variant]}`}
    >
      {children}
    </button>
  )
}

export function TextInput({
  value,
  onChange,
  placeholder,
  type = 'text',
  className = ''
}: {
  value: string
  onChange: (value: string) => void
  placeholder?: string
  type?: string
  className?: string
}): React.JSX.Element {
  return (
    <input
      type={type}
      value={value}
      placeholder={placeholder}
      onChange={(event) => onChange(event.target.value)}
      className={`rounded-lg border border-line bg-bg-elevated px-3 py-1.5 text-[13px] text-ink outline-none placeholder:text-faint focus:border-accent ${className}`}
    />
  )
}

export function Select<T extends string>({
  value,
  onChange,
  options,
  className = ''
}: {
  value: T
  onChange: (value: T) => void
  options: Array<{ value: T; label: string }>
  className?: string
}): React.JSX.Element {
  return (
    <select
      value={value}
      onChange={(event) => onChange(event.target.value as T)}
      className={`rounded-lg border border-line bg-bg-elevated px-2.5 py-1.5 text-[13px] text-ink outline-none focus:border-accent ${className}`}
    >
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  )
}

export function Toggle({
  checked,
  onChange,
  label,
  help
}: {
  checked: boolean
  onChange: (value: boolean) => void
  label: string
  help?: string
}): React.JSX.Element {
  return (
    <label className="flex cursor-pointer items-start gap-3 py-2">
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        onClick={() => onChange(!checked)}
        className={`mt-0.5 h-5 w-9 shrink-0 rounded-full border transition-colors ${
          checked ? 'border-transparent bg-accent' : 'border-line bg-panel-hover'
        }`}
      >
        <span
          className={`block h-4 w-4 rounded-full bg-white transition-transform ${
            checked ? 'translate-x-[18px] rtl:-translate-x-[18px]' : 'translate-x-0.5 rtl:-translate-x-0.5'
          }`}
        />
      </button>
      <span>
        <span className="block text-[13px] text-ink">{label}</span>
        {help && <span className="mt-0.5 block text-xs leading-relaxed text-muted">{help}</span>}
      </span>
    </label>
  )
}

export function EmptyState({ title, hint }: { title: string; hint?: string }): React.JSX.Element {
  return (
    <div className="flex flex-col items-center justify-center gap-1 px-4 py-12 text-center">
      <div className="text-sm text-muted">{title}</div>
      {hint && <div className="text-xs text-faint">{hint}</div>}
    </div>
  )
}

export function PageHeader({
  title,
  description,
  children
}: {
  title: string
  description?: string
  children?: ReactNode
}): React.JSX.Element {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-lg font-semibold text-ink">{title}</h1>
        {description && <p className="mt-1 max-w-3xl text-xs leading-relaxed text-muted">{description}</p>}
      </div>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Range picker                                                        */
/* ------------------------------------------------------------------ */

const RANGE_KEYS: Array<{ value: TimeRange; key: TranslationKey }> = [
  { value: '1m', key: 'range.1m' },
  { value: '5m', key: 'range.5m' },
  { value: '15m', key: 'range.15m' },
  { value: '1h', key: 'range.1h' },
  { value: '24h', key: 'range.24h' },
  { value: '7d', key: 'range.7d' },
  { value: '30d', key: 'range.30d' }
]

export function RangePicker({
  value,
  onChange,
  ranges
}: {
  value: TimeRange
  onChange: (value: TimeRange) => void
  ranges?: TimeRange[]
}): React.JSX.Element {
  const { t } = useApp()
  const allowed = ranges ? RANGE_KEYS.filter((r) => ranges.includes(r.value)) : RANGE_KEYS
  return (
    <Select
      value={value}
      onChange={onChange}
      options={allowed.map((r) => ({ value: r.value, label: t(r.key) }))}
    />
  )
}

/* ------------------------------------------------------------------ */
/* Sortable, searchable table                                          */
/* ------------------------------------------------------------------ */

export interface Column<T> {
  key: string
  header: string
  render: (row: T) => ReactNode
  /** Value used for sorting; omit to make the column unsortable. */
  sortValue?: (row: T) => string | number
  width?: string
  align?: 'start' | 'end'
}

export function DataTable<T>({
  rows,
  columns,
  rowKey,
  onRowClick,
  emptyTitle,
  emptyHint,
  maxHeight = '100%',
  initialSort
}: {
  rows: T[]
  columns: Array<Column<T>>
  rowKey: (row: T) => string
  onRowClick?: (row: T) => void
  emptyTitle: string
  emptyHint?: string
  maxHeight?: string
  initialSort?: { key: string; dir: 'asc' | 'desc' }
}): React.JSX.Element {
  const [sort, setSort] = useState<{ key: string; dir: 'asc' | 'desc' } | null>(initialSort ?? null)

  const sorted = useMemo(() => {
    if (!sort) return rows
    const column = columns.find((c) => c.key === sort.key)
    if (!column?.sortValue) return rows
    const factor = sort.dir === 'asc' ? 1 : -1
    return [...rows].sort((a, b) => {
      const left = column.sortValue!(a)
      const right = column.sortValue!(b)
      if (typeof left === 'number' && typeof right === 'number') return (left - right) * factor
      return String(left).localeCompare(String(right)) * factor
    })
  }, [rows, columns, sort])

  if (rows.length === 0) return <EmptyState title={emptyTitle} hint={emptyHint} />

  const toggleSort = (key: string): void => {
    setSort((prev) =>
      prev?.key === key ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'desc' }
    )
  }

  return (
    <div className="overflow-auto" style={{ maxHeight }}>
      <table className="w-full border-collapse text-[13px]">
        <thead className="sticky top-0 z-10 bg-panel">
          <tr className="border-b border-line">
            {columns.map((column) => (
              <th
                key={column.key}
                style={{ width: column.width }}
                onClick={column.sortValue ? () => toggleSort(column.key) : undefined}
                className={`whitespace-nowrap px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-faint ${
                  column.align === 'end' ? 'text-end' : 'text-start'
                } ${column.sortValue ? 'cursor-pointer select-none hover:text-ink' : ''}`}
              >
                {column.header}
                {sort?.key === column.key && <span className="ms-1 text-accent">{sort.dir === 'asc' ? '↑' : '↓'}</span>}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((row) => (
            <tr
              key={rowKey(row)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              className={`border-b border-line/60 ${onRowClick ? 'cursor-pointer' : ''} hover:bg-panel-hover`}
            >
              {columns.map((column) => (
                <td
                  key={column.key}
                  className={`px-3 py-1.5 align-middle ${column.align === 'end' ? 'text-end' : 'text-start'}`}
                >
                  {column.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
