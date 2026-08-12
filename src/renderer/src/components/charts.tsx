import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from 'recharts'
import type { TrafficSample } from '@shared/types'
import { formatBytes, formatTime } from '../format'
import { EmptyState } from './ui'

/** Chart palette shared by every visualisation, tuned for both themes. */
export const SERIES_COLORS = ['#38bdf8', '#34d399', '#a78bfa', '#fbbf24', '#f87171', '#22d3ee', '#f472b6', '#94a3b8']

const axisStyle = { fontSize: 11, fill: 'var(--text-faint)' }
const gridStroke = 'var(--grid)'

function TooltipBox({
  active,
  payload,
  label,
  valueFormatter
}: {
  active?: boolean
  payload?: Array<{ name?: string; value?: number | string; color?: string }>
  label?: string | number
  valueFormatter: (value: number) => string
}): React.JSX.Element | null {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border border-line bg-bg-elevated px-3 py-2 text-xs shadow-lg">
      {label !== undefined && <div className="mb-1 text-faint">{typeof label === 'number' ? formatTime(label) : label}</div>}
      {payload.map((entry, index) => (
        <div key={index} className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full" style={{ background: entry.color }} />
          <span className="text-muted">{entry.name}</span>
          <span className="tnum ms-auto font-medium text-ink">
            {typeof entry.value === 'number' ? valueFormatter(entry.value) : entry.value}
          </span>
        </div>
      ))}
    </div>
  )
}

export function TrafficAreaChart({
  data,
  height = 240,
  emptyLabel
}: {
  data: TrafficSample[]
  height?: number
  emptyLabel: string
}): React.JSX.Element {
  if (data.length === 0) return <EmptyState title={emptyLabel} />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <AreaChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 8 }}>
        <defs>
          <linearGradient id="gradDown" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.45} />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity={0.02} />
          </linearGradient>
          <linearGradient id="gradUp" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#34d399" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#34d399" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={gridStroke} strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="ts" tickFormatter={formatTime} tick={axisStyle} stroke={gridStroke} minTickGap={40} />
        <YAxis tickFormatter={(v: number) => formatBytes(v, 0)} tick={axisStyle} stroke={gridStroke} width={62} />
        <Tooltip content={<TooltipBox valueFormatter={(v) => formatBytes(v)} />} />
        <Legend wrapperStyle={{ fontSize: 11, color: 'var(--text-muted)' }} />
        <Area
          type="monotone"
          dataKey="bytesDown"
          name="Download"
          stroke="#38bdf8"
          strokeWidth={1.6}
          fill="url(#gradDown)"
          isAnimationActive={false}
        />
        <Area
          type="monotone"
          dataKey="bytesUp"
          name="Upload"
          stroke="#34d399"
          strokeWidth={1.6}
          fill="url(#gradUp)"
          isAnimationActive={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}

export function PacketsLineChart({
  data,
  height = 200,
  emptyLabel
}: {
  data: TrafficSample[]
  height?: number
  emptyLabel: string
}): React.JSX.Element {
  if (data.length === 0) return <EmptyState title={emptyLabel} />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <LineChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: 8 }}>
        <CartesianGrid stroke={gridStroke} strokeDasharray="3 3" vertical={false} />
        <XAxis dataKey="ts" tickFormatter={formatTime} tick={axisStyle} stroke={gridStroke} minTickGap={40} />
        <YAxis tick={axisStyle} stroke={gridStroke} width={50} />
        <Tooltip content={<TooltipBox valueFormatter={(v) => `${Math.round(v)}`} />} />
        <Line
          type="monotone"
          dataKey="packets"
          name="Packets"
          stroke="#a78bfa"
          strokeWidth={1.6}
          dot={false}
          isAnimationActive={false}
        />
      </LineChart>
    </ResponsiveContainer>
  )
}

export function HorizontalBars({
  data,
  height = 220,
  emptyLabel
}: {
  data: Array<{ label: string; value: number }>
  height?: number
  emptyLabel: string
}): React.JSX.Element {
  if (data.length === 0) return <EmptyState title={emptyLabel} />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 8 }}>
        <CartesianGrid stroke={gridStroke} strokeDasharray="3 3" horizontal={false} />
        <XAxis type="number" tickFormatter={(v: number) => formatBytes(v, 0)} tick={axisStyle} stroke={gridStroke} />
        <YAxis type="category" dataKey="label" tick={axisStyle} stroke={gridStroke} width={140} />
        <Tooltip cursor={{ fill: 'var(--panel-hover)' }} content={<TooltipBox valueFormatter={(v) => formatBytes(v)} />} />
        <Bar dataKey="value" name="Bytes" radius={[0, 4, 4, 0]} isAnimationActive={false}>
          {data.map((_, index) => (
            <Cell key={index} fill={SERIES_COLORS[index % SERIES_COLORS.length]} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export function ProtocolPie({
  data,
  height = 220,
  emptyLabel
}: {
  data: Array<{ label: string; value: number }>
  height?: number
  emptyLabel: string
}): React.JSX.Element {
  if (data.length === 0) return <EmptyState title={emptyLabel} />
  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie
          data={data}
          dataKey="value"
          nameKey="label"
          innerRadius="52%"
          outerRadius="80%"
          paddingAngle={2}
          isAnimationActive={false}
          stroke="var(--panel)"
        >
          {data.map((_, index) => (
            <Cell key={index} fill={SERIES_COLORS[index % SERIES_COLORS.length]} />
          ))}
        </Pie>
        <Tooltip content={<TooltipBox valueFormatter={(v) => formatBytes(v)} />} />
        <Legend wrapperStyle={{ fontSize: 11, color: 'var(--text-muted)' }} />
      </PieChart>
    </ResponsiveContainer>
  )
}
