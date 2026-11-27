import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { AlertCircle, Eye, EyeOff, Lock, Moon, ShieldCheck, Sun, Wifi, WifiOff } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { useHealthQuery, useReadinessQuery } from '../hooks/useHealth';
import { loginSchema } from '../utils/validators';
import { BrandLogo } from '../components/layout/BrandLogo';
import { Button } from '../components/ui/Button';
import { Input } from '../components/ui/Input';

export function Login() {
  const { login, sessionNotice, clearNotice, authMode } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const location = useLocation();
  const fromPath = location.state?.from?.pathname || '/';

  const healthQuery = useHealthQuery();
  const readinessQuery = useReadinessQuery();

  const [showKey, setShowKey] = useState(false);
  const [authError, setAuthError] = useState(null);
  const [submitting, setSubmitting] = useState(false);

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(loginSchema),
    defaultValues: { adminKey: '', actor: '' },
  });

  const apiConnected = healthQuery.isSuccess && healthQuery.data?.status === 'ok';
  const dbReady = readinessQuery.isSuccess && readinessQuery.data?.database === 'connected';

  const onSubmit = async (values) => {
    setAuthError(null);
    clearNotice();
    setSubmitting(true);
    try {
      await login({
        adminKey: values.adminKey,
        actor: values.actor,
      });
      navigate(fromPath, { replace: true });
    } catch (err) {
      setAuthError(err.message || 'Authentication failed.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex min-h-screen flex-col justify-between bg-slate-50 px-4 py-8 dark:bg-obsidian-950">
      <div className="mx-auto flex w-full max-w-md items-center justify-between">
        <BrandLogo />
        <button
          type="button"
          onClick={toggleTheme}
          aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
          className="rounded-md border border-slate-200 bg-white p-2 text-slate-600 hover:bg-slate-100 dark:border-slate-800 dark:bg-obsidian-900 dark:text-slate-300 dark:hover:bg-obsidian-800"
        >
          {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>
      </div>

      <main className="mx-auto w-full max-w-md">
        <div className="rounded-lg border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800/80 dark:bg-obsidian-900 sm:p-8">
          <div className="flex items-center justify-between gap-2">
            <div>
              <h1 className="text-lg font-semibold tracking-tight text-slate-900 dark:text-slate-100">
                Administrator Sign In
              </h1>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                Authenticate against the AXLY Chaperone control plane.
              </p>
            </div>
            <div className="flex h-9 w-9 items-center justify-center rounded-md border border-slate-200 bg-slate-50 text-slate-600 dark:border-slate-800 dark:bg-obsidian-850 dark:text-slate-300">
              <Lock className="h-4 w-4" />
            </div>
          </div>

          {/* Live backend probe status */}
          <div className="mt-4 flex items-center justify-between rounded-md border border-slate-200 bg-slate-50 px-3 py-2 text-xs dark:border-slate-800 dark:bg-obsidian-950">
            <span className="flex items-center gap-2 text-slate-600 dark:text-slate-400">
              {apiConnected ? (
                <Wifi className="h-3.5 w-3.5 text-emerald-500" />
              ) : (
                <WifiOff className="h-3.5 w-3.5 text-rose-500" />
              )}
              {healthQuery.isLoading
                ? 'Checking gateway connectivity...'
                : apiConnected
                  ? `Gateway v${healthQuery.data.version} online`
                  : 'Gateway unreachable'}
            </span>
            {apiConnected && (
              <span
                className={
                  dbReady
                    ? 'font-medium text-emerald-600 dark:text-emerald-400'
                    : 'font-medium text-amber-600 dark:text-amber-400'
                }
              >
                {dbReady ? 'DB Ready' : 'DB Unavailable'}
              </span>
            )}
          </div>

          {sessionNotice && (
            <div
              role="status"
              className="mt-4 flex items-start gap-2.5 rounded-md border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200"
            >
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
              <p>{sessionNotice.message}</p>
            </div>
          )}

          {authError && (
            <div
              role="alert"
              className="mt-4 flex items-start gap-2.5 rounded-md border border-rose-300 bg-rose-50 p-3 text-xs text-rose-800 dark:border-rose-500/40 dark:bg-rose-500/10 dark:text-rose-200"
            >
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600 dark:text-rose-400" />
              <p>{authError}</p>
            </div>
          )}

          {authMode === 'session_cookie' ? (
            <div className="mt-5 space-y-4">
              <p className="text-xs text-slate-600 dark:text-slate-300">
                Console is configured for HTTP-only cookie session mode. Ensure your identity
                provider session cookie is active, then verify access below.
              </p>
              <Button
                className="w-full"
                isLoading={submitting}
                onClick={() => onSubmit({ adminKey: 'cookie-session', actor: '' })}
              >
                Verify Cookie Session
              </Button>
            </div>
          ) : (
            <form onSubmit={handleSubmit(onSubmit)} className="mt-5 space-y-4" noValidate>
              <div className="relative">
                <Input
                  label="Admin API Key (X-Admin-Key)"
                  type={showKey ? 'text' : 'password'}
                  mono
                  autoComplete="current-password"
                  placeholder="axly_adm_..."
                  error={errors.adminKey?.message}
                  className="pr-10"
                  {...register('adminKey')}
                />
                <button
                  type="button"
                  onClick={() => setShowKey((prev) => !prev)}
                  aria-label={showKey ? 'Hide admin key' : 'Show admin key'}
                  className="absolute right-2.5 top-[30px] rounded p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
                >
                  {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>

              <Input
                label="Reviewer / Actor Identity (optional)"
                placeholder="e.g. secops-lead"
                hint="Optional X-Admin-Actor attribution for approvals. Cross-origin setups must include X-Admin-Actor in CHAPERONE_CORS_ALLOW_HEADERS."
                error={errors.actor?.message}
                {...register('actor')}
              />

              <Button type="submit" className="w-full" isLoading={submitting}>
                <ShieldCheck className="h-4 w-4" />
                Authenticate Session
              </Button>
            </form>
          )}

          <div className="mt-5 border-t border-slate-200 pt-4 text-[11px] leading-relaxed text-slate-500 dark:border-slate-800 dark:text-slate-400">
            Credentials are verified directly with the backend API and held strictly in browser
            memory for this session — never written to <code>localStorage</code> or client bundles.
          </div>
        </div>
      </main>

      <footer className="mx-auto w-full max-w-md text-center text-[11px] text-slate-500 dark:text-slate-500">
        AXLY Chaperone · Safe autonomy. Human control.
      </footer>
    </div>
  );
}
