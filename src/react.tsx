/**
 * React surface for @skyemeta/skyegate.
 *
 * Subpath import: `import { useSkyeGate, GatedContent } from '@skyemeta/skyegate/react'`.
 * React is a peer dependency — only import this entry point in a React app.
 */

import { useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  verifyConditions,
  type Condition,
  type VerifyConditionsParams,
} from './index.js';

export type GateStatus = 'idle' | 'verifying' | 'pass' | 'fail' | 'error';

export interface UseSkyeGateOptions {
  /** Wallet address from your wallet stack (wagmi, RainbowKit, etc.). Null/undefined keeps the hook idle. */
  address: string | null | undefined;
  /** Conditions to verify — same shape as {@link Condition}. */
  conditions: Condition[];
  /** Your SKYE license key. Safe to expose as `NEXT_PUBLIC_SKYE_LICENSE_KEY` since the proxy enforces domain locking. */
  licenseKey: string;
  /** `"evm"` (default) or `"solana"`. */
  walletType?: VerifyConditionsParams['walletType'];
  /** Override the verification endpoint. */
  endpoint?: string;
  /** When false, the hook stays idle and never calls the proxy. Default true. */
  enabled?: boolean;
}

export interface UseSkyeGateResult {
  status: GateStatus;
  pass: boolean;
  jwt: string | null;
  error: string | null;
  /** Trigger a re-verification with the same parameters. */
  refetch: () => void;
}

/**
 * React hook that runs `verifyConditions` and tracks its lifecycle.
 *
 * Re-runs when `address`, `licenseKey`, `walletType`, `endpoint`, or the
 * serialized `conditions` change.
 */
export function useSkyeGate(options: UseSkyeGateOptions): UseSkyeGateResult {
  const [status, setStatus] = useState<GateStatus>('idle');
  const [jwt, setJwt] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  const enabled = options.enabled !== false;
  const conditionsKey = useMemo(() => JSON.stringify(options.conditions), [options.conditions]);

  useEffect(() => {
    if (!enabled || !options.address) {
      setStatus('idle');
      setJwt(null);
      setError(null);
      return;
    }

    let cancelled = false;
    setStatus('verifying');
    setJwt(null);
    setError(null);

    verifyConditions({
      address: options.address,
      conditions: options.conditions,
      licenseKey: options.licenseKey,
      walletType: options.walletType,
      endpoint: options.endpoint,
    })
      .then((result) => {
        if (cancelled) return;
        setJwt(result.jwt);
        if (result.pass) {
          setStatus('pass');
        } else if (result.error) {
          setStatus('error');
          setError(result.error);
        } else {
          setStatus('fail');
        }
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        setStatus('error');
        setError(err instanceof Error ? err.message : 'Verification failed');
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    enabled,
    options.address,
    options.licenseKey,
    options.walletType,
    options.endpoint,
    conditionsKey,
    tick,
  ]);

  return {
    status,
    pass: status === 'pass',
    jwt,
    error,
    refetch: () => setTick((t) => t + 1),
  };
}

export interface GatedContentProps extends UseSkyeGateOptions {
  /** Rendered when the gate passes. */
  children: ReactNode;
  /** Rendered when the gate fails or errors. */
  fallback?: ReactNode;
  /** Rendered while verifying. */
  loading?: ReactNode;
  /** Called once when the gate first passes. JWT can be POSTed to your server to fetch gated content. */
  onPass?: (jwt: string) => void;
}

/**
 * Declarative gate. Renders `children` only when the wallet meets the conditions.
 *
 * @example
 * ```tsx
 * import { GatedContent } from '@skyemeta/skyegate/react';
 * import { useAccount } from 'wagmi';
 *
 * export default function Page() {
 *   const { address } = useAccount();
 *   return (
 *     <GatedContent
 *       address={address}
 *       conditions={[{ type: 'farcaster_id' }]}
 *       licenseKey={process.env.NEXT_PUBLIC_SKYE_LICENSE_KEY!}
 *       loading={<p>Verifying...</p>}
 *       fallback={<p>Connect a Farcaster-linked wallet to see this.</p>}
 *     >
 *       <h2>Welcome, Farcaster user.</h2>
 *     </GatedContent>
 *   );
 * }
 * ```
 */
export function GatedContent(props: GatedContentProps) {
  const { children, fallback = null, loading = null, onPass, ...gateOptions } = props;
  const result = useSkyeGate(gateOptions);

  useEffect(() => {
    if (result.status === 'pass' && result.jwt && onPass) {
      onPass(result.jwt);
    }
  }, [result.status, result.jwt, onPass]);

  if (result.status === 'verifying') return <>{loading}</>;
  if (result.status === 'pass') return <>{children}</>;
  return <>{fallback}</>;
}

export type { Condition };
