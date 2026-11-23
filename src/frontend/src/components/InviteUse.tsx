import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useMutation } from '@tanstack/react-query'
import { invitesApi } from '../lib/api'
import { Moon, Sun } from 'lucide-react'

function DarkToggle() {
  const [dark, setDark] = useState(document.documentElement.classList.contains('dark'))
  function toggle() {
    const next = !dark
    setDark(next)
    if (next) { document.documentElement.classList.add('dark'); localStorage.setItem('theme', 'dark') }
    else { document.documentElement.classList.remove('dark'); localStorage.setItem('theme', 'light') }
  }
  return (
    <div className="flex items-center gap-2">
      <Moon className="w-3.5 h-3.5 text-gray-400 dark:text-gray-500" />
      <button
        onClick={toggle}
        title={dark ? 'Light mode' : 'Dark mode'}
        className={`relative inline-flex w-9 h-5 shrink-0 rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none ${dark ? 'bg-brand-500' : 'bg-gray-300'}`}
      >
        <span className={`inline-block w-4 h-4 rounded-full bg-white shadow transform transition-transform duration-200 ${dark ? 'translate-x-4' : 'translate-x-0'}`} />
      </button>
      <Sun className="w-3.5 h-3.5 text-gray-400 dark:text-gray-500" />
    </div>
  )
}

export default function InviteUse() {
  const { token: urlToken } = useParams<{ token?: string }>()
  const navigate = useNavigate()
  const [token, setToken] = useState(urlToken ?? '')
  const [name, setName] = useState('')

  // Initialize dark mode (self-contained, outside Layout)
  useEffect(() => {
    if (localStorage.getItem('theme') !== 'light') {
      document.documentElement.classList.add('dark')
    }
  }, [])

  const mutation = useMutation({
    mutationFn: () => invitesApi.use({ token, name }),
    onSuccess: (data) => navigate(data.setup_url, { replace: true }),
  })

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="flex justify-end mb-4">
          <DarkToggle />
        </div>
        <div className="bg-white dark:bg-gray-800 rounded-2xl p-8 shadow-xl">
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-1">Join OurClaude</h1>
          <p className="text-gray-500 dark:text-gray-400 mb-6">Enter your invite token and choose a name to get your API token.</p>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Invite token</label>
              <input
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-500 font-mono text-sm dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
                value={token}
                onChange={e => setToken(e.target.value)}
                placeholder="Paste your invite token here"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Your name</label>
              <input
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:outline-none focus:ring-2 focus:ring-brand-500 text-sm dark:bg-gray-700 dark:text-white dark:placeholder-gray-400"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="Alice"
                onKeyDown={e => e.key === 'Enter' && !mutation.isPending && token && name && mutation.mutate()}
              />
            </div>
            {mutation.isError && (
              <p className="text-sm text-red-600">{(mutation.error as Error).message}</p>
            )}
          </div>

          <button
            onClick={() => mutation.mutate()}
            disabled={!token || !name || mutation.isPending}
            className="mt-6 w-full px-4 py-2.5 bg-brand-500 text-white rounded-lg text-sm font-medium hover:bg-brand-600 disabled:opacity-50 transition-colors"
          >
            {mutation.isPending ? 'Creating account...' : 'Create account'}
          </button>
        </div>
      </div>
    </div>
  )
}
