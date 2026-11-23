import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { poolsApi, accountsApi, Pool, Account, User } from '../lib/api'
import { ArrowLeft, Server, Users, Zap, AlertTriangle, CheckCircle, Link2Off, Plus, X, Clock, Clock3 } from 'lucide-react'

function fmtTokens(n: number) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M'
  if (n >= 1_000) return (n / 1_000).toFixed(0) + 'K'
  return String(n)
}

function fmtCost(n: number) {
  if (!n || n === 0) return '—'
  if (n < 0.01) return '<$0.01'
  return '$' + n.toFixed(2)
}

function StatCard({ label, requests, input, output, cost }: {
  label: string
  requests: number
  input: number
  output: number
  cost?: number
}) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-5">
      <p className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-3">{label}</p>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <p className="text-2xl font-bold text-gray-900 dark:text-white">{requests.toLocaleString()}</p>
          <p className="text-xs text-gray-500 dark:text-gray-400">requests</p>
        </div>
        <div>
          {cost !== undefined && <p className="text-xl font-bold text-amber-600">{fmtCost(cost)}</p>}
          <p className="text-xs text-gray-500 dark:text-gray-400">est. cost</p>
        </div>
        <div>
          <p className="text-sm font-semibold text-blue-600 dark:text-blue-400">{fmtTokens(input)}</p>
          <p className="text-xs text-gray-500 dark:text-gray-400">input tokens</p>
        </div>
        <div>
          <p className="text-sm font-semibold text-purple-600 dark:text-purple-400">{fmtTokens(output)}</p>
          <p className="text-xs text-gray-500 dark:text-gray-400">output tokens</p>
        </div>
      </div>
    </div>
  )
}

function AccountStatusBadge({ status }: { status: string }) {
  if (status === 'active') return <span className="flex items-center gap-1 text-green-600 dark:text-green-400 text-xs"><CheckCircle className="w-3.5 h-3.5" />Active</span>
  if (status === 'exhausted') return <span className="flex items-center gap-1 text-yellow-600 dark:text-yellow-400 text-xs"><Zap className="w-3.5 h-3.5" />Exhausted</span>
  if (status === 'disabled') return <span className="flex items-center gap-1 text-gray-400 text-xs"><Clock className="w-3.5 h-3.5" />Disabled</span>
  return <span className="flex items-center gap-1 text-red-600 dark:text-red-400 text-xs"><AlertTriangle className="w-3.5 h-3.5" />Error</span>
}

function ConfirmModal({ title, message, confirmLabel, onConfirm, onCancel, danger }: {
  title: string; message: string; confirmLabel?: string
  onConfirm: () => void; onCancel: () => void; danger?: boolean
}) {
  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-2xl p-6 w-full max-w-sm shadow-2xl max-h-[90dvh] overflow-y-auto">
        <h3 className="text-lg font-semibold dark:text-white mb-2">{title}</h3>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">{message}</p>
        <div className="flex gap-3">
          <button onClick={onCancel} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm hover:bg-gray-50 dark:hover:bg-gray-700 dark:text-gray-300">Cancel</button>
          <button onClick={onConfirm} className={`flex-1 px-4 py-2 text-white rounded-lg text-sm ${danger ? 'bg-red-500 hover:bg-red-600' : 'bg-brand-500 hover:bg-brand-600'}`}>
            {confirmLabel ?? 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  )
}

function AccountRow({ account, poolId }: { account: Account; poolId: number }) {
  const navigate = useNavigate()
  const [showConfirm, setShowConfirm] = useState(false)
  const qc = useQueryClient()
  const { data: stats } = useQuery({
    queryKey: ['account-stats', account.id],
    queryFn: () => accountsApi.stats(account.id),
  })

  const unlinkMutation = useMutation({
    mutationFn: () => accountsApi.unlink(account.id, poolId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['pool-stats', poolId] })
      qc.invalidateQueries({ queryKey: ['accounts'] })
      qc.invalidateQueries({ queryKey: ['pools'] })
    },
  })

  return (
    <>
      <tr className="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer" onClick={() => navigate('/accounts/' + account.id)}>
        <td className="px-5 py-3">
          <p className="text-sm font-medium text-gray-900 dark:text-white">{account.name}</p>
          <p className="text-xs text-gray-400 dark:text-gray-500">
            Expires {new Date(account.expires_at).toLocaleDateString()}
          </p>
        </td>
        <td className="px-5 py-3"><AccountStatusBadge status={account.status} /></td>
        <td className="px-5 py-3 text-sm text-gray-600 dark:text-gray-400">
          {stats ? fmtTokens(stats.today.input_tokens + stats.today.output_tokens) : '—'}
        </td>
        <td className="px-5 py-3 text-sm text-gray-600 dark:text-gray-400">
          {stats ? fmtTokens(stats.week.input_tokens + stats.week.output_tokens) : '—'}
        </td>
        <td className="px-5 py-3 text-xs text-gray-400 dark:text-gray-500">
          {account.last_used_at ? new Date(account.last_used_at).toLocaleString() : '—'}
        </td>
        <td className="px-5 py-3 text-right" onClick={e => e.stopPropagation()}>
          <button
            title="Unlink from pool"
            onClick={() => setShowConfirm(true)}
            disabled={unlinkMutation.isPending}
            className="p-1.5 text-gray-400 hover:text-purple-500 rounded disabled:opacity-50"
          >
            <Link2Off className="w-4 h-4" />
          </button>
        </td>
      </tr>
      {showConfirm && (
        <ConfirmModal
          title="Unlink account"
          message={`Remove "${account.name}" from this pool?`}
          confirmLabel="Unlink"
          onConfirm={() => { unlinkMutation.mutate(); setShowConfirm(false) }}
          onCancel={() => setShowConfirm(false)}
        />
      )}
    </>
  )
}

function ResetSchedule({ pool }: { pool: Pool }) {
  const [resetAt, setResetAt] = useState('')
  const [error, setError] = useState('')
  const qc = useQueryClient()
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ['pool-stats', pool.id] })
    qc.invalidateQueries({ queryKey: ['pools'] })
    setError('')
  }
  const schedule = useMutation({
    mutationFn: () => poolsApi.scheduleReset(pool.id, new Date(resetAt).toISOString()),
    onSuccess: () => { setResetAt(''); refresh() },
    onError: (e: Error) => setError(e.message),
  })
  const cancel = useMutation({
    mutationFn: () => poolsApi.cancelScheduledReset(pool.id),
    onSuccess: refresh,
    onError: (e: Error) => setError(e.message),
  })
  const validFuture = resetAt && !Number.isNaN(new Date(resetAt).getTime()) && new Date(resetAt).getTime() > Date.now()

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-5">
      <h2 className="font-semibold text-gray-900 dark:text-white text-sm flex items-center gap-2"><Clock3 className="w-4 h-4 text-gray-500" /> Scheduled reset</h2>
      <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">Reactivate exhausted accounts in this pool once at a chosen time. This is off until you schedule it.</p>
      {pool.scheduled_reset_at && (
        <div className="flex items-center gap-3 flex-wrap mt-3 text-sm">
          <span className="text-gray-700 dark:text-gray-300">Next reset: <strong>{new Date(pool.scheduled_reset_at).toLocaleString()}</strong></span>
          <button type="button" onClick={() => cancel.mutate()} disabled={cancel.isPending} className="text-red-600 dark:text-red-400 hover:underline disabled:opacity-50">Cancel reset</button>
        </div>
      )}
      <div className="flex items-end gap-3 flex-wrap mt-4">
        <label className="text-sm text-gray-700 dark:text-gray-300">
          Date and time (your local time)
          <input type="datetime-local" value={resetAt} onChange={e => setResetAt(e.target.value)} className="block mt-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg dark:bg-gray-700 dark:text-white" />
        </label>
        <button type="button" onClick={() => schedule.mutate()} disabled={!validFuture || schedule.isPending} className="px-4 py-2 bg-brand-500 text-white rounded-lg text-sm hover:bg-brand-600 disabled:opacity-50">
          {pool.scheduled_reset_at ? 'Reschedule' : 'Schedule reset'}
        </button>
      </div>
      <p className="text-xs text-gray-500 dark:text-gray-400 mt-3">To receive a reminder, subscribe a webhook to <code>pool.reset.reminder</code>. It fires five hours before the reset, or shortly after scheduling if the reset is sooner.</p>
      {error && <p className="text-sm text-red-600 mt-2">{error}</p>}
    </div>
  )
}

function AddAccountsModal({ poolId, existingIds, onClose }: {
  poolId: number; existingIds: Set<number>; onClose: () => void
}) {
  const qc = useQueryClient()
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [search, setSearch] = useState('')
  const [error, setError] = useState('')
  const { data: allAccounts = [], isLoading } = useQuery({ queryKey: ['accounts'], queryFn: accountsApi.list })

  const q = search.trim().toLowerCase()
  const available = allAccounts.filter(a => !existingIds.has(a.id))
  const shown = available.filter(a => !q || a.name.toLowerCase().includes(q))

  const toggle = (accId: number) => {
    const next = new Set(selected)
    if (next.has(accId)) next.delete(accId); else next.add(accId)
    setSelected(next)
  }

  const mutation = useMutation({
    mutationFn: () => poolsApi.addAccounts(poolId, [...selected]),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['pool-stats', poolId] })
      qc.invalidateQueries({ queryKey: ['accounts'] })
      qc.invalidateQueries({ queryKey: ['pools'] })
      onClose()
    },
    onError: (e: Error) => setError(e.message),
  })

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-white dark:bg-gray-800 rounded-2xl p-6 w-full max-w-lg shadow-2xl flex flex-col max-h-[85vh]" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold dark:text-white">Add accounts to pool</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200"><X className="w-5 h-5" /></button>
        </div>

        {available.length > 0 && (
          <input
            className="w-full px-3 py-2 mb-3 border border-gray-300 dark:border-gray-600 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-brand-500 dark:bg-gray-700 dark:text-white"
            placeholder="Filter by name…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            autoFocus
          />
        )}

        <div className="flex-1 overflow-y-auto -mx-2">
          {isLoading ? (
            <p className="px-2 py-6 text-center text-sm text-gray-400">Loading accounts…</p>
          ) : available.length === 0 ? (
            <p className="px-2 py-6 text-center text-sm text-gray-400 dark:text-gray-500">Every account is already in this pool.</p>
          ) : shown.length === 0 ? (
            <p className="px-2 py-6 text-center text-sm text-gray-400 dark:text-gray-500">No accounts match "{search}".</p>
          ) : (
            shown.map(a => (
              <label
                key={a.id}
                className={`flex items-center gap-3 px-2 py-2 rounded-lg cursor-pointer ${selected.has(a.id) ? 'bg-brand-50 dark:bg-brand-900/30' : 'hover:bg-gray-50 dark:hover:bg-gray-700/50'}`}
              >
                <input type="checkbox" className="accent-brand-500" checked={selected.has(a.id)} onChange={() => toggle(a.id)} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                    {a.name}
                    {a.account_type === 'apikey' && <span className="ml-1.5 text-xs font-normal text-gray-400">API key</span>}
                  </p>
                  <p className="text-xs text-gray-400 dark:text-gray-500 truncate">
                    {(a.pools ?? []).length > 0 ? 'In: ' + (a.pools ?? []).map(p => p.name).join(', ') : 'Not in any pool'}
                  </p>
                </div>
                <AccountStatusBadge status={a.status} />
              </label>
            ))
          )}
        </div>

        {error && <p className="text-sm text-red-600 mt-3">{error}</p>}

        <div className="flex gap-3 mt-4">
          <button onClick={onClose} className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm hover:bg-gray-50 dark:hover:bg-gray-700 dark:text-gray-300">
            Cancel
          </button>
          <button
            onClick={() => mutation.mutate()}
            disabled={selected.size === 0 || mutation.isPending}
            className="flex-1 px-4 py-2 bg-brand-500 text-white rounded-lg text-sm hover:bg-brand-600 disabled:opacity-50"
          >
            {mutation.isPending ? 'Adding…' : selected.size > 0 ? `Add ${selected.size} account${selected.size !== 1 ? 's' : ''}` : 'Add'}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function PoolDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const poolId = Number(id)
  const [showAdd, setShowAdd] = useState(false)

  const { data: statsData, isLoading: statsLoading } = useQuery({
    queryKey: ['pool-stats', poolId],
    queryFn: () => poolsApi.stats(poolId),
    enabled: !!poolId,
  })

  const { data: users = [], isLoading: usersLoading } = useQuery({
    queryKey: ['pool-users', poolId],
    queryFn: () => poolsApi.users(poolId),
    enabled: !!poolId,
  })

  const pool = statsData?.pool

  if (statsLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-brand-500" />
      </div>
    )
  }

  if (!pool) {
    return (
      <div className="text-center py-20">
        <p className="text-gray-500 dark:text-gray-400">Pool not found.</p>
        <button onClick={() => navigate('/pools')} className="mt-4 text-brand-500 hover:underline text-sm">← Back to pools</button>
      </div>
    )
  }

  const accounts = pool.accounts ?? []

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start gap-4">
        <button
          onClick={() => navigate('/pools')}
          className="mt-1 p-1.5 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div className="flex-1">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">{pool.name}</h1>
          {pool.description && <p className="text-gray-500 dark:text-gray-400 mt-0.5">{pool.description}</p>}
          <div className="flex items-center gap-4 mt-2 text-xs text-gray-400 dark:text-gray-500">
            {pool.daily_token_quota > 0 && <span>Daily quota: {fmtTokens(pool.daily_token_quota)}</span>}
            {pool.monthly_token_quota > 0 && <span>Monthly quota: {fmtTokens(pool.monthly_token_quota)}</span>}
          </div>
          {(pool.daily_token_quota > 0 || pool.monthly_token_quota > 0) && statsData && (
            <div className="flex flex-col gap-2 mt-3 max-w-md">
              {pool.daily_token_quota > 0 && (() => {
                const used = statsData.today.input_tokens + statsData.today.output_tokens
                const pct = Math.min(100, (used / pool.daily_token_quota) * 100)
                return (
                  <div>
                    <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400 mb-1">
                      <span>Daily usage</span>
                      <span>{fmtTokens(used)} / {fmtTokens(pool.daily_token_quota)} ({pct.toFixed(0)}%)</span>
                    </div>
                    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full transition-all ${pct >= 90 ? 'bg-red-500' : pct >= 70 ? 'bg-yellow-500' : 'bg-brand-500'}`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                )
              })()}
              {pool.monthly_token_quota > 0 && (() => {
                const used = statsData.month.input_tokens + statsData.month.output_tokens
                const pct = Math.min(100, (used / pool.monthly_token_quota) * 100)
                return (
                  <div>
                    <div className="flex items-center justify-between text-xs text-gray-500 dark:text-gray-400 mb-1">
                      <span>Monthly usage</span>
                      <span>{fmtTokens(used)} / {fmtTokens(pool.monthly_token_quota)} ({pct.toFixed(0)}%)</span>
                    </div>
                    <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full transition-all ${pct >= 90 ? 'bg-red-500' : pct >= 70 ? 'bg-yellow-500' : 'bg-brand-500'}`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                )
              })()}
            </div>
          )}
        </div>
      </div>

      <ResetSchedule pool={pool} />

      {/* Stats cards */}
      {statsData && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <StatCard
            label="Today"
            requests={statsData.today.requests}
            input={statsData.today.input_tokens}
            output={statsData.today.output_tokens}
            cost={statsData.today.est_cost_usd}
          />
          <StatCard
            label="Last 7 days"
            requests={statsData.week.requests}
            input={statsData.week.input_tokens}
            output={statsData.week.output_tokens}
            cost={statsData.week.est_cost_usd}
          />
          <StatCard
            label="This month"
            requests={statsData.month.requests}
            input={statsData.month.input_tokens}
            output={statsData.month.output_tokens}
            cost={statsData.month.est_cost_usd}
          />
        </div>
      )}

      {/* Accounts */}
      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100 dark:border-gray-700 flex items-center gap-2">
          <Server className="w-4 h-4 text-gray-500 dark:text-gray-400" />
          <h2 className="font-semibold text-gray-900 dark:text-white text-sm">{accounts.length} Account{accounts.length !== 1 ? 's' : ''}</h2>
          <button
            onClick={() => setShowAdd(true)}
            className="ml-auto flex items-center gap-1.5 px-3 py-1.5 bg-brand-500 text-white rounded-lg text-xs font-medium hover:bg-brand-600"
          >
            <Plus className="w-3.5 h-3.5" />
            Add accounts
          </button>
        </div>
        {accounts.length === 0 ? (
          <div className="px-5 py-8 text-center text-gray-400 dark:text-gray-500 text-sm">No accounts in this pool.</div>
        ) : (
          <div className="table-scroll"><table className="w-full text-sm">
            <thead className="bg-gray-50 dark:bg-gray-700/50 text-xs text-gray-500 dark:text-gray-400 uppercase">
              <tr>
                <th className="px-5 py-2.5 text-left">Account</th>
                <th className="px-5 py-2.5 text-left">Status</th>
                <th className="px-5 py-2.5 text-left">Tokens today</th>
                <th className="px-5 py-2.5 text-left">Tokens this week</th>
                <th className="px-5 py-2.5 text-left">Last used</th>
                <th className="px-5 py-2.5 text-right"></th>
              </tr>
            </thead>
            <tbody>
              {accounts.map((acc: Account) => <AccountRow key={acc.id} account={acc} poolId={poolId} />)}
            </tbody>
          </table></div>
        )}
      </div>

      {/* Users */}
      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100 dark:border-gray-700 flex items-center gap-2">
          <Users className="w-4 h-4 text-gray-500 dark:text-gray-400" />
          <h2 className="font-semibold text-gray-900 dark:text-white text-sm">
            {usersLoading ? '…' : users.length} User{users.length !== 1 ? 's' : ''} assigned
          </h2>
        </div>
        {users.length === 0 ? (
          <div className="px-5 py-8 text-center text-gray-400 dark:text-gray-500 text-sm">No users assigned to this pool.</div>
        ) : (
          <div className="table-scroll"><table className="w-full text-sm">
            <thead className="bg-gray-50 dark:bg-gray-700/50 text-xs text-gray-500 dark:text-gray-400 uppercase">
              <tr>
                <th className="px-5 py-2.5 text-left">Name</th>
                <th className="px-5 py-2.5 text-left">Status</th>
                <th className="px-5 py-2.5 text-left">Daily quota</th>
                <th className="px-5 py-2.5 text-left">Monthly quota</th>
                <th className="px-5 py-2.5 text-left">Created</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u: User) => (
                <tr key={u.id} className="border-b border-gray-100 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800">
                  <td className="px-5 py-3 font-medium text-gray-900 dark:text-white">{u.name}</td>
                  <td className="px-5 py-3">
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${u.active ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
                      {u.active ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td className="px-5 py-3 text-gray-500 dark:text-gray-400 text-xs">{u.daily_token_quota ? fmtTokens(u.daily_token_quota) : 'Unlimited'}</td>
                  <td className="px-5 py-3 text-gray-500 dark:text-gray-400 text-xs">{u.monthly_token_quota ? fmtTokens(u.monthly_token_quota) : 'Unlimited'}</td>
                  <td className="px-5 py-3 text-gray-400 dark:text-gray-500 text-xs">{new Date(u.created_at).toLocaleDateString()}</td>
                </tr>
              ))}
            </tbody>
          </table></div>
        )}
      </div>

      {showAdd && (
        <AddAccountsModal
          poolId={poolId}
          existingIds={new Set(accounts.map((a: Account) => a.id))}
          onClose={() => setShowAdd(false)}
        />
      )}
    </div>
  )
}
