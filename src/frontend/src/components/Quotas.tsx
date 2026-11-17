import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { quotasApi, poolsApi, AccountQuotaWithInfo, Pool } from '../lib/api'
import { AlertTriangle, CheckCircle, Clock, XCircle, RefreshCw, ExternalLink, MinusCircle } from 'lucide-react'

const CHATGPT_USAGE_URL = 'https://chatgpt.com/settings/usage'

type Severity = 'critical' | 'warning' | 'healthy' | 'unknown'

function hasSnapshot(q: AccountQuotaWithInfo): boolean {
  return !!q.source || (!q.error && new Date(q.updated_at).getFullYear() > 1970)
}

function isPlanAccount(q: AccountQuotaWithInfo): boolean {
  return q.oauth_provider === 'siwc' && !hasSnapshot(q)
}

function severity(q: AccountQuotaWithInfo): Severity {
  if (q.limit_reached || q.allowed === false || q.status === 'exhausted') return 'critical'
  if (q.error) return 'unknown'
  if (isPlanAccount(q)) return q.status === 'exhausted' ? 'critical' : 'unknown'
  if (!hasSnapshot(q)) return 'unknown'
  if (!q.primary_window_minutes && !q.primary_resets && !q.secondary_window_minutes && !q.secondary_resets && q.allowed !== true) return 'unknown'
  const maxPct = Math.max(q.primary_pct, q.secondary_pct)
  return maxPct >= 90 ? 'critical' : maxPct >= 70 ? 'warning' : 'healthy'
}

const severityRank: Record<Severity, number> = { critical: 0, warning: 1, healthy: 2, unknown: 3 }

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`
  return String(n)
}

function formatSince(iso: string): string {
  const mins = Math.floor((Date.now() - new Date(iso).getTime()) / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  return hours < 48 ? `${hours}h ${mins % 60}m ago` : new Date(iso).toLocaleString()
}

function PlanAccountCard({ q }: { q: AccountQuotaWithInfo }) {
  const limited = q.status === 'exhausted'
  const inRotation = q.status === 'active' || limited
  return (
    <div className={`bg-white dark:bg-gray-800 rounded-xl border p-5 transition-colors ${
      limited ? 'border-red-300 dark:border-red-800' : 'border-gray-200 dark:border-gray-700'
    }`}>
      <div className="flex items-start gap-3 mb-4">
        {limited ? <XCircle className="w-5 h-5 text-red-500" />
          : <MinusCircle className="w-5 h-5 text-gray-400" />}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-gray-900 dark:text-white text-sm truncate">{q.account_name}</span>
            <span className={`px-1.5 py-0.5 rounded text-xs font-medium shrink-0 ${
              q.status === 'active' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' :
              limited ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400' :
              q.status === 'error' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
              'bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400'
            }`}>{q.status}</span>
          </div>
          <div className="flex flex-wrap gap-1 mt-1">
            <span className="px-1.5 py-0.5 bg-brand-50 dark:bg-brand-900/30 text-brand-600 dark:text-brand-100 rounded text-xs">ChatGPT plan</span>
            {(q.pools ?? []).map(p => (
              <span key={p.id} className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 rounded text-xs">{p.name}</span>
            ))}
          </div>
        </div>
      </div>

      <div className={`rounded-lg p-3 text-xs ${
        limited ? 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400'
          : inRotation ? 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400'
          : 'bg-gray-50 dark:bg-gray-700/50 text-gray-500 dark:text-gray-400'
      }`}>
        {limited
          ? <>Usage limit reached{q.exhausted_at ? ` ${formatSince(q.exhausted_at)}` : ''}. Requests go to other accounts until this one completes a response again.</>
          : inRotation
            ? <>No limit reported yet. Remaining quota is unknown.</>
            : <>Not in rotation while {q.status}.</>}
      </div>

      <div className="mt-3 rounded-lg bg-gray-50 dark:bg-gray-700/50 p-3 text-xs text-gray-600 dark:text-gray-300">
        <div className="flex justify-between"><span>5-hour remaining</span><strong>Unknown</strong></div>
        <div className="flex justify-between mt-1"><span>Weekly remaining</span><strong>Unknown</strong></div>
        {q.last_used_at && <p className="mt-2 text-gray-500 dark:text-gray-400">Last request {new Date(q.last_used_at).toLocaleString()}</p>}
        {(q.error || q.last_error) && <p className="mt-2 text-red-600 dark:text-red-400">Quota fetch: {q.error || q.last_error}</p>}
      </div>

      <div className="mt-3 space-y-1.5 text-xs">
        <p className="font-medium text-gray-700 dark:text-gray-300">Served through OurCodex</p>
        {([['Last 5 hours', q.usage_5h], ['Last 7 days', q.usage_7d]] as const).map(([label, usage]) => (
          <div key={label} className="flex justify-between text-gray-500 dark:text-gray-400">
            <span>{label}</span>
            <span className="font-mono">{formatTokens(usage?.tokens ?? 0)} tokens · {usage?.requests ?? 0} req</span>
          </div>
        ))}
      </div>

      <div className="mt-3 pt-3 border-t border-gray-100 dark:border-gray-700 flex items-center justify-between gap-2">
        <p className="text-xs text-gray-400 dark:text-gray-500">Awaiting an OpenAI quota snapshot for this sign-in.</p>
        <a href={CHATGPT_USAGE_URL} target="_blank" rel="noreferrer"
          className="flex items-center gap-1 text-xs font-medium text-brand-500 hover:underline shrink-0">
          Manage usage <ExternalLink className="w-3 h-3" />
        </a>
      </div>
    </div>
  )
}

function UsageBar({ label, pct, resets, color, showRemaining = false }: { label: string; pct: number; resets?: string; color?: string; showRemaining?: boolean }) {
  const barColor = color ?? (pct >= 90 ? 'bg-red-500' : pct >= 70 ? 'bg-amber-500' : pct >= 40 ? 'bg-blue-500' : 'bg-green-500')
  const textColor = pct >= 90 ? 'text-red-600 dark:text-red-400 font-semibold' : pct >= 70 ? 'text-amber-600 dark:text-amber-400' : 'text-gray-600 dark:text-gray-400'
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs font-medium text-gray-700 dark:text-gray-300">{label}</span>
        <span className={`text-xs ${textColor}`}>{showRemaining ? `${Math.max(0, 100 - pct).toFixed(1)}% left` : `${pct}% used`}{resets ? ` — ${formatReset(resets)}` : ''}</span>
      </div>
      <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2.5">
        <div className={`h-2.5 rounded-full transition-all duration-500 ${barColor}`} style={{ width: `${Math.min(pct, 100)}%` }} />
      </div>
    </div>
  )
}

function formatReset(iso: string): string {
  if (!iso) return ''
  try {
    const t = new Date(iso)
    const now = new Date()
    const diffMs = t.getTime() - now.getTime()
    if (diffMs <= 0) return 'resetting...'
    const hours = Math.floor(diffMs / 3600000)
    const mins = Math.floor((diffMs % 3600000) / 60000)
    if (hours < 1) return `resets in ${mins}m`
    if (hours < 5) return `resets in ${hours}h ${mins}m`
    return `resets ${t.toLocaleDateString()} ${t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`
  } catch {
    return iso
  }
}

function StatusIcon({ pct }: { pct: number }) {
  if (pct >= 90) return <XCircle className="w-5 h-5 text-red-500" />
  if (pct >= 70) return <AlertTriangle className="w-5 h-5 text-amber-500" />
  if (pct >= 40) return <Clock className="w-5 h-5 text-blue-500" />
  return <CheckCircle className="w-5 h-5 text-green-500" />
}

function AccountQuotaCard({ q }: { q: AccountQuotaWithInfo }) {
  const maxPct = Math.max(q.primary_pct, q.secondary_pct)

  return (
    <div className={`bg-white dark:bg-gray-800 rounded-xl border p-5 transition-colors ${
      maxPct >= 90 ? 'border-red-300 dark:border-red-800' :
      maxPct >= 70 ? 'border-amber-300 dark:border-amber-800' :
      'border-gray-200 dark:border-gray-700'
    }`}>
      <div className="flex items-start gap-3 mb-4">
        <StatusIcon pct={maxPct} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-semibold text-gray-900 dark:text-white text-sm truncate">{q.account_name}</span>
            <span className={`px-1.5 py-0.5 rounded text-xs font-medium shrink-0 ${
              q.status === 'active' ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' :
              q.status === 'exhausted' ? 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400' :
              q.status === 'error' ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' :
              'bg-gray-100 text-gray-500 dark:bg-gray-700 dark:text-gray-400'
            }`}>{q.status}</span>
          </div>
          {(q.pools ?? []).length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1">
              {q.pools!.map(p => (
                <span key={p.id} className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 text-gray-500 dark:text-gray-400 rounded text-xs">{p.name}</span>
              ))}
            </div>
          )}
        </div>
      </div>

      {!hasSnapshot(q) ? (
        <p className="text-xs text-gray-500 dark:text-gray-400">Remaining quota unknown. Waiting for the account usage fetch.</p>
      ) : (
        <div className="space-y-3">
          {q.error && <p className="text-xs text-red-600 dark:text-red-400">Latest refresh failed: {q.error}. Showing the last snapshot.</p>}
          {q.plan_type && <p className="text-xs text-gray-500 dark:text-gray-400">{q.plan_type} plan · {q.source === 'usage_api' ? 'OpenAI account usage' : 'response headers'}</p>}
          {(q.primary_window_minutes || q.primary_resets) && <UsageBar label={`Primary${q.primary_window_minutes ? ` (${q.primary_window_minutes}m)` : ''}`} pct={q.primary_pct} resets={q.primary_resets} showRemaining />}
          {(q.secondary_window_minutes || q.secondary_resets) && <UsageBar label={`Secondary${q.secondary_window_minutes ? ` (${q.secondary_window_minutes}m)` : ''}`} pct={q.secondary_pct} resets={q.secondary_resets} showRemaining />}
          {!q.primary_window_minutes && !q.primary_resets && !q.secondary_window_minutes && !q.secondary_resets && <p className="text-xs text-gray-500 dark:text-gray-400">No timed quota windows reported for this plan.</p>}
          {q.credits_has && (
            <div className="mt-2 pt-2 border-t border-gray-100 dark:border-gray-700">
              <div className="flex justify-between text-xs text-gray-500 dark:text-gray-400">
                <span>Credits</span>
                <span>{q.credits_unlimited ? 'Unlimited' : q.credits_balance || 'Available'}</span>
              </div>
            </div>
          )}
        </div>
      )}

      <p className="text-xs text-gray-400 dark:text-gray-500 mt-3">
        {(() => {
          const updated = new Date(q.updated_at)
          const ageMs = Date.now() - updated.getTime()
          if (updated.getFullYear() <= 1970 || ageMs < 0) {
            return <>No data yet — waiting for an account usage read</>
          }
          const ageHours = Math.floor(ageMs / 3600000)
          const ageMins = Math.floor(ageMs / 60000)
          const timeStr = ageMins < 1 ? 'just now' : ageMins < 60 ? `${ageMins}m ago` : `${ageHours}h ago`
          return <>Updated {timeStr}</>
        })()}
        {(() => {
          const updated = new Date(q.updated_at)
          const ageMs = Date.now() - updated.getTime()
          const ageHours = Math.floor(ageMs / 3600000)
          if (updated.getFullYear() > 1970 && ageHours >= 1) {
            return <span className="ml-2 text-orange-500 font-medium">{'\u26A0'} Data from {ageHours}h ago</span>
          }
          return null
        })()}
      </p>
    </div>
  )
}

export default function Quotas() {
  const [filter, setFilter] = useState<'all' | Severity>('all')
  const [poolFilter, setPoolFilter] = useState<string>('')

  const { data: quotas = [], isLoading, isFetching, refetch } = useQuery({
    queryKey: ['openai-quotas'],
    queryFn: quotasApi.all,
    refetchInterval: 10_000,
  })

  const refreshMutation = useMutation({
    mutationFn: quotasApi.refresh,
    onSuccess: () => { void refetch() },
  })

  const { data: pools = [] } = useQuery({ queryKey: ['pools'], queryFn: poolsApi.list })

  // Filter logic
  const filtered = quotas.filter(q => {
    if (poolFilter) {
      const inPool = (q.pools ?? []).some(p => String(p.id) === poolFilter)
      if (!inPool) return false
    }
    return filter === 'all' || severity(q) === filter
  })

  // Summary stats
  const critical = quotas.filter(q => severity(q) === 'critical').length
  const warning = quotas.filter(q => severity(q) === 'warning').length
  const healthy = quotas.filter(q => severity(q) === 'healthy').length
  const unknown = quotas.filter(q => severity(q) === 'unknown').length
  const errored = quotas.filter(q => q.error).length

  // Pool averages, over accounts that report rate-limit percentages
  const poolAverages = pools.map(p => {
    const poolQuotas = quotas.filter(q => hasSnapshot(q) &&
      (q.primary_window_minutes || q.primary_resets) && (q.secondary_window_minutes || q.secondary_resets) &&
      (q.pools ?? []).some(pp => pp.id === p.id))
    if (poolQuotas.length === 0) return { pool: p, avgFive: 0, avgSeven: 0, count: 0 }
    const avgFive = Math.round(poolQuotas.reduce((s, q) => s + q.primary_pct, 0) / poolQuotas.length)
    const avgSeven = Math.round(poolQuotas.reduce((s, q) => s + q.secondary_pct, 0) / poolQuotas.length)
    return { pool: p, avgFive, avgSeven, count: poolQuotas.length }
  }).filter(p => p.count > 0)

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="h-8 bg-gray-200 dark:bg-gray-700 rounded w-48 animate-pulse" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[...Array(4)].map((_, i) => <div key={i} className="h-24 bg-gray-200 dark:bg-gray-700 rounded-xl animate-pulse" />)}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">OpenAI Quotas</h1>
          <p className="text-gray-500 dark:text-gray-400 mt-1">
            Remaining percentages come from each account's OpenAI usage endpoint or recent response headers.
          </p>
        </div>
        <button
          onClick={() => refreshMutation.mutate()}
          disabled={refreshMutation.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-brand-500 text-white rounded-lg text-sm hover:bg-brand-600 disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${isFetching || refreshMutation.isPending ? 'animate-spin' : ''}`} />
          {refreshMutation.isPending ? 'Starting...' : 'Refresh quotas'}
        </button>
      </div>
      {refreshMutation.isError && <p className="text-sm text-red-500">Could not start quota refresh: {(refreshMutation.error as Error).message}</p>}

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <button onClick={() => setFilter(filter === 'critical' ? 'all' : 'critical')}
          className={`bg-white dark:bg-gray-800 rounded-xl border p-4 text-left transition-colors ${filter === 'critical' ? 'border-red-500 ring-1 ring-red-500' : 'border-gray-200 dark:border-gray-700'}`}>
          <div className="flex items-center gap-2 mb-1">
            <XCircle className="w-4 h-4 text-red-500" />
            <span className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Critical</span>
          </div>
          <p className="text-2xl font-bold text-red-600">{critical}</p>
        </button>
        <button onClick={() => setFilter(filter === 'warning' ? 'all' : 'warning')}
          className={`bg-white dark:bg-gray-800 rounded-xl border p-4 text-left transition-colors ${filter === 'warning' ? 'border-amber-500 ring-1 ring-amber-500' : 'border-gray-200 dark:border-gray-700'}`}>
          <div className="flex items-center gap-2 mb-1">
            <AlertTriangle className="w-4 h-4 text-amber-500" />
            <span className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Warning</span>
          </div>
          <p className="text-2xl font-bold text-amber-600">{warning}</p>
        </button>
        <button onClick={() => setFilter(filter === 'healthy' ? 'all' : 'healthy')}
          className={`bg-white dark:bg-gray-800 rounded-xl border p-4 text-left transition-colors ${filter === 'healthy' ? 'border-green-500 ring-1 ring-green-500' : 'border-gray-200 dark:border-gray-700'}`}>
          <div className="flex items-center gap-2 mb-1">
            <CheckCircle className="w-4 h-4 text-green-500" />
            <span className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Healthy</span>
          </div>
          <p className="text-2xl font-bold text-green-600">{healthy}</p>
        </button>
        <button onClick={() => setFilter(filter === 'unknown' ? 'all' : 'unknown')}
          className={`bg-white dark:bg-gray-800 rounded-xl border p-4 text-left transition-colors ${filter === 'unknown' ? 'border-gray-500 ring-1 ring-gray-500' : 'border-gray-200 dark:border-gray-700'}`}>
          <div className="flex items-center gap-2 mb-1">
            <MinusCircle className="w-4 h-4 text-gray-500" />
            <span className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Unknown</span>
          </div>
          <p className="text-2xl font-bold text-gray-600 dark:text-gray-300">{unknown}</p>
        </button>
        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase">Errors</span>
          </div>
          <p className="text-2xl font-bold text-gray-400">{errored}</p>
        </div>
      </div>

      {/* Color legend */}
      <div className="flex items-center gap-4 text-xs text-gray-500">
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full bg-red-500" /> 90%+</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full bg-amber-500" /> 70-89%</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-full bg-green-500" /> &lt;70%</span>
      </div>

      {/* Pool averages */}
      {poolAverages.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-3">Pool Averages</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {poolAverages.map(({ pool, avgFive, avgSeven, count }) => (
              <button key={pool.id} onClick={() => setPoolFilter(poolFilter === String(pool.id) ? '' : String(pool.id))}
                className={`bg-white dark:bg-gray-800 rounded-xl border p-4 text-left transition-colors ${poolFilter === String(pool.id) ? 'border-brand-500 ring-1 ring-brand-500' : 'border-gray-200 dark:border-gray-700'}`}>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-medium text-gray-900 dark:text-white text-sm">{pool.name}</span>
                  <span className="text-xs text-gray-400">{count} accounts</span>
                </div>
                <div className="space-y-1.5">
                  <UsageBar label="Avg session" pct={avgFive} />
                  <UsageBar label="Avg weekly" pct={avgSeven} />
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3">
        <span className="text-sm text-gray-500 dark:text-gray-400">
          {filtered.length} account{filtered.length !== 1 ? 's' : ''}
          {filter !== 'all' && ` (${filter})`}
          {poolFilter && ` in ${pools.find(p => String(p.id) === poolFilter)?.name}`}
        </span>
        {(filter !== 'all' || poolFilter) && (
          <button onClick={() => { setFilter('all'); setPoolFilter('') }}
            className="text-xs text-brand-500 hover:underline">Clear filters</button>
        )}
      </div>

      {/* Account cards */}
      {filtered.length === 0 ? (
        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-8 text-center text-gray-400">
          {quotas.length === 0 ? 'No quota data yet — send a Codex request through the proxy first.' : 'No accounts match the current filter.'}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered
            .sort((a, b) => severityRank[severity(a)] - severityRank[severity(b)]
              || Math.max(b.primary_pct, b.secondary_pct) - Math.max(a.primary_pct, a.secondary_pct))
            .map(q => isPlanAccount(q)
              ? <PlanAccountCard key={q.account_id} q={q} />
              : <AccountQuotaCard key={q.account_id} q={q} />)}
        </div>
      )}
    </div>
  )
}
