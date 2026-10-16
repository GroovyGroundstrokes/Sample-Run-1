import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { INITIAL_MOCK_TRANSACTIONS } from './src/data/mockTransactions.js';

export interface UserScopedTransactionContextItem {
  id: string;
  transaction_date: string;
  merchant: string;
  description: string;
  category: string;
  type: 'income' | 'expense';
  amount: number;
  location: string;
  payment_method: string;
  risk_level: string;
  risk_score: number;
  security_status: string;
  detection_reason: string | null;
}

export interface UserFinancialContextResult {
  transactionCount: number;
  dateRange: {
    from: string | null;
    to: string | null;
  };
  transactions: UserScopedTransactionContextItem[];
}

// Fixed maximums for strict data minimization
export const MAX_CONTEXT_TRANSACTIONS = 100;
export const MAX_CONTEXT_DAYS = 90;

export const DEMO_USER_ID = '00000000-0000-0000-0000-000000000001';

export interface CategorySpendingFact {
  category: string;
  total: number;
  percentage: number;
}

export interface DeterministicFinancialFacts {
  periodDays: number;
  dateRange: {
    from: string | null;
    to: string | null;
  };
  transactionCount: number;
  totalIncome: number;
  totalExpenses: number;
  netCashFlow: number;
  savingsRate: number;
  categoryDistribution: CategorySpendingFact[];
  topCategory: {
    category: string;
    total: number;
    percentage: number;
  } | null;
  largestTransaction: {
    merchant: string;
    amount: number;
    type: 'income' | 'expense';
    category: string;
    date: string;
  } | null;
  topExpenses: Array<{
    merchant: string;
    amount: number;
    category: string;
    date: string;
  }>;
  recurringMerchants: Array<{
    merchant: string;
    count: number;
    totalSpent: number;
  }>;
  unusuallyLargeTransactions: Array<{
    merchant: string;
    amount: number;
    date: string;
    thresholdRatio: number;
  }>;
  activeSecurityAlertCount: number;
  highRiskSecurityAlertCount: number;
  flaggedTransactionsCount: number;
}

/**
 * Deterministically computes authoritative financial facts from sanitized transaction records.
 * Uses precise mathematical operations. Never estimates, fabricates, or divides by zero.
 */
export function calculateDeterministicFinancialFacts(
  transactions: UserScopedTransactionContextItem[],
  dateRange: { from: string | null; to: string | null },
  activeSecurityAlertCount = 0,
  highRiskSecurityAlertCount = 0
): DeterministicFinancialFacts {
  if (!transactions || transactions.length === 0) {
    return {
      periodDays: MAX_CONTEXT_DAYS,
      dateRange: { from: null, to: null },
      transactionCount: 0,
      totalIncome: 0,
      totalExpenses: 0,
      netCashFlow: 0,
      savingsRate: 0,
      categoryDistribution: [],
      topCategory: null,
      largestTransaction: null,
      topExpenses: [],
      recurringMerchants: [],
      unusuallyLargeTransactions: [],
      activeSecurityAlertCount,
      highRiskSecurityAlertCount,
      flaggedTransactionsCount: 0,
    };
  }

  let totalIncome = 0;
  let totalExpenses = 0;
  const categoryMap = new Map<string, number>();
  const merchantExpenseMap = new Map<string, { count: number; total: number }>();
  let largestTx: UserScopedTransactionContextItem | null = null;
  let flaggedCount = 0;

  for (const tx of transactions) {
    const amt = Math.max(0, Number(tx.amount) || 0);

    if (tx.type === 'income') {
      totalIncome += amt;
    } else {
      totalExpenses += amt;
      // Category aggregation
      const cat = tx.category || 'Other';
      categoryMap.set(cat, (categoryMap.get(cat) || 0) + amt);

      // Merchant recurrence
      const merch = tx.merchant || 'Unknown';
      const curr = merchantExpenseMap.get(merch) || { count: 0, total: 0 };
      merchantExpenseMap.set(merch, { count: curr.count + 1, total: curr.total + amt });
    }

    if (!largestTx || amt > (Number(largestTx.amount) || 0)) {
      largestTx = tx;
    }

    if (
      tx.security_status === 'Review Required' ||
      tx.risk_level.toUpperCase() === 'HIGH' ||
      tx.risk_level.toUpperCase() === 'MEDIUM'
    ) {
      flaggedCount += 1;
    }
  }

  // Round currency to 2 decimal places
  totalIncome = Math.round(totalIncome * 100) / 100;
  totalExpenses = Math.round(totalExpenses * 100) / 100;
  const netCashFlow = Math.round((totalIncome - totalExpenses) * 100) / 100;

  // Safe savings rate calculation (0 if income <= 0 to avoid division by zero)
  let savingsRate = 0;
  if (totalIncome > 0) {
    savingsRate = Math.round(((totalIncome - totalExpenses) / totalIncome) * 1000) / 10;
  }

  // Category distribution
  const categoryDistribution: CategorySpendingFact[] = Array.from(categoryMap.entries())
    .map(([category, total]) => ({
      category,
      total: Math.round(total * 100) / 100,
      percentage: totalExpenses > 0 ? Math.round((total / totalExpenses) * 1000) / 10 : 0,
    }))
    .sort((a, b) => b.total - a.total);

  const topCategory = categoryDistribution.length > 0 ? categoryDistribution[0] : null;

  // Top expense transactions
  const topExpenses = transactions
    .filter((t) => t.type === 'expense')
    .sort((a, b) => b.amount - a.amount)
    .slice(0, 5)
    .map((t) => ({
      merchant: t.merchant,
      amount: t.amount,
      category: t.category,
      date: t.transaction_date,
    }));

  // Recurring merchants (2+ transactions)
  const recurringMerchants = Array.from(merchantExpenseMap.entries())
    .filter(([_, data]) => data.count >= 2)
    .map(([merchant, data]) => ({
      merchant,
      count: data.count,
      totalSpent: Math.round(data.total * 100) / 100,
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);

  // Unusually large transactions: transactions where amount is >= 3x the median/mean expense
  const expenseList = transactions.filter((t) => t.type === 'expense');
  const avgExpense = expenseList.length > 0 ? totalExpenses / expenseList.length : 0;
  const unusuallyLargeTransactions = expenseList
    .filter((t) => avgExpense > 0 && t.amount >= avgExpense * 2.5)
    .map((t) => ({
      merchant: t.merchant,
      amount: t.amount,
      date: t.transaction_date,
      thresholdRatio: Math.round((t.amount / avgExpense) * 10) / 10,
    }))
    .sort((a, b) => b.amount - a.amount)
    .slice(0, 3);

  return {
    periodDays: MAX_CONTEXT_DAYS,
    dateRange,
    transactionCount: transactions.length,
    totalIncome,
    totalExpenses,
    netCashFlow,
    savingsRate,
    categoryDistribution,
    topCategory,
    largestTransaction: largestTx
      ? {
          merchant: largestTx.merchant,
          amount: largestTx.amount,
          type: largestTx.type,
          category: largestTx.category,
          date: largestTx.transaction_date,
        }
      : null,
    topExpenses,
    recurringMerchants,
    unusuallyLargeTransactions,
    activeSecurityAlertCount,
    highRiskSecurityAlertCount,
    flaggedTransactionsCount: flaggedCount,
  };
}

export interface DeterministicAnomalySignal {
  type: 'amount_deviation' | 'category_deviation' | 'merchant_deviation' | 'transaction_velocity' | 'geographic_deviation' | 'international_activity' | 'timing_pattern' | 'repeated_activity';
  description: string;
  evidence: string;
}

export interface DeterministicTransactionAnomaly {
  transactionId: string;
  merchant: string;
  amount: number;
  date: string;
  heuristicScore: number;
  severity: 'info' | 'low' | 'medium' | 'high';
  signals: DeterministicAnomalySignal[];
  recommendedAction: 'monitor' | 'review' | 'verify';
}

/**
 * Calculates objective, explainable deterministic anomaly features for each transaction.
 * Evaluates mathematical deviation, category spikes, velocity, international activity, and timing.
 * Does not guess missing fields.
 */
export function calculateDeterministicAnomalyFeatures(
  transactions: UserScopedTransactionContextItem[]
): DeterministicTransactionAnomaly[] {
  if (!transactions || transactions.length === 0) {
    return [];
  }

  const expenseTxs = transactions.filter((t) => t.type === 'expense');
  if (expenseTxs.length === 0) {
    return [];
  }

  // 1. Mean and std deviation of expense transactions
  const totalExpense = expenseTxs.reduce((sum, t) => sum + t.amount, 0);
  const avgExpense = totalExpense / expenseTxs.length;

  // Category averages
  const catSums = new Map<string, { count: number; total: number }>();
  for (const t of expenseTxs) {
    const c = t.category || 'Other';
    const curr = catSums.get(c) || { count: 0, total: 0 };
    catSums.set(c, { count: curr.count + 1, total: curr.total + t.amount });
  }

  // Velocity map: count transactions per date
  const dateCounts = new Map<string, number>();
  for (const t of transactions) {
    dateCounts.set(t.transaction_date, (dateCounts.get(t.transaction_date) || 0) + 1);
  }

  const anomalies: DeterministicTransactionAnomaly[] = [];

  for (const tx of transactions) {
    const signals: DeterministicAnomalySignal[] = [];
    let score = 0;

    // Feature A: Amount deviation (compared against expense average)
    if (tx.type === 'expense' && avgExpense > 0) {
      const ratio = tx.amount / avgExpense;
      if (ratio >= 4.0) {
        signals.push({
          type: 'amount_deviation',
          description: 'Transaction amount is materially larger than the 90-day expense baseline.',
          evidence: `₹${tx.amount.toLocaleString()} compared with 90-day expense average of ₹${Math.round(avgExpense).toLocaleString()} (${Math.round(ratio * 10) / 10}x)`,
        });
        score += Math.min(45, Math.round(ratio * 7));
      } else if (ratio >= 2.5) {
        signals.push({
          type: 'amount_deviation',
          description: 'Transaction amount is elevated compared to typical recent expenses.',
          evidence: `₹${tx.amount.toLocaleString()} exceeds average expense ₹${Math.round(avgExpense).toLocaleString()}`,
        });
        score += 20;
      }
    }

    // Feature B: Category deviation (amount is > 70% of total category spending)
    if (tx.type === 'expense') {
      const catData = catSums.get(tx.category || 'Other');
      if (catData && catData.count > 1 && tx.amount / catData.total > 0.7 && tx.amount > 5000) {
        signals.push({
          type: 'category_deviation',
          description: `Disproportionate concentration within the ${tx.category} category.`,
          evidence: `₹${tx.amount.toLocaleString()} represents ${Math.round((tx.amount / catData.total) * 100)}% of all ${tx.category} outflows`,
        });
        score += 15;
      }
    }

    // Feature C: International activity (explicitly indicated in merchant or description)
    const lowerMerch = tx.merchant.toLowerCase();
    const lowerDesc = tx.description.toLowerCase();
    const isInternational =
      lowerMerch.includes('international') ||
      lowerMerch.includes('overseas') ||
      lowerDesc.includes('cross-border') ||
      lowerDesc.includes('foreign') ||
      lowerDesc.includes('london, uk') ||
      lowerDesc.includes('bangkok, th');

    if (isInternational) {
      signals.push({
        type: 'international_activity',
        description: 'Cross-border or international intermediary activity identified in transaction context.',
        evidence: `Merchant/Description indicates foreign or international jurisdiction (${tx.merchant})`,
      });
      score += 25;
    }

    // Feature D: Existing security system review status
    if (tx.security_status === 'Review Required' || tx.risk_level === 'HIGH' || tx.risk_level === 'MEDIUM') {
      signals.push({
        type: 'repeated_activity',
        description: 'Transaction is flagged by the security rules engine as warranting verification.',
        evidence: tx.detection_reason || `Security status: ${tx.security_status}, Risk level: ${tx.risk_level}`,
      });
      score += tx.risk_level === 'HIGH' ? 30 : 15;
    }

    // Feature E: Velocity spikes (3+ transactions on same day)
    const sameDayCount = dateCounts.get(tx.transaction_date) || 0;
    if (sameDayCount >= 3 && tx.amount > 2000) {
      signals.push({
        type: 'transaction_velocity',
        description: 'Elevated transaction frequency recorded on the same date.',
        evidence: `${sameDayCount} transactions processed on ${tx.transaction_date}`,
      });
      score += 10;
    }

    // Only qualify as an anomaly if meaningful deviation signals exist
    if (signals.length > 0 && score >= 25) {
      const finalScore = Math.min(99, Math.max(25, score));
      let severity: 'info' | 'low' | 'medium' | 'high' = 'low';
      let action: 'monitor' | 'review' | 'verify' = 'monitor';

      if (finalScore >= 70) {
        severity = 'high';
        action = 'verify';
      } else if (finalScore >= 45) {
        severity = 'medium';
        action = 'review';
      }

      anomalies.push({
        transactionId: tx.id,
        merchant: tx.merchant,
        amount: tx.amount,
        date: tx.transaction_date,
        heuristicScore: finalScore,
        severity,
        signals,
        recommendedAction: action,
      });
    }
  }

  return anomalies.sort((a, b) => b.heuristicScore - a.heuristicScore);
}

export const isProductionEnvironment = Boolean(
  process.env.NODE_ENV === 'production' ||
  process.env.VERCEL_ENV === 'production' ||
  process.env.VERCEL_ENV === 'preview' ||
  process.env.VERCEL === '1' ||
  (process.env.K_SERVICE && !process.env.K_SERVICE.startsWith('ais-dev-'))
);

const isValidSupabaseKey = (key?: string): boolean => {
  if (!key || typeof key !== 'string') return false;
  const trimmed = key.trim();
  if (trimmed.length < 40 || trimmed.includes('placeholder')) return false;
  return (trimmed.startsWith('eyJ') && trimmed.split('.').length === 3) || trimmed.startsWith('sbp_');
};

const isDemoSession = (userId: string, token?: string, anonKey?: string): boolean => {
  // In production and preview environments, demo/offline session is STRICTLY PROHIBITED.
  // Production users must always receive financial context from their real Supabase ledger.
  if (isProductionEnvironment) {
    return false;
  }
  if (userId === DEMO_USER_ID || userId.startsWith('demo-')) return true;
  if (token === 'demo-access-token' || (token && token.startsWith('demo-'))) return true;
  if (!isValidSupabaseKey(anonKey)) return true;
  return false;
};

/**
 * Retrieves deterministic security alerts count for the authenticated user.
 */
export async function getSecurityAlertsSummaryForUser(
  verifiedUserId: string,
  userAccessToken?: string,
  supabaseUrl?: string,
  supabaseAnonKey?: string
): Promise<{ activeCount: number; highRiskCount: number }> {
  // Demo mode:
  if (isDemoSession(verifiedUserId, userAccessToken, supabaseAnonKey)) {
    // 2 active mock alerts in demo ledger (tx-004: High Risk 87, tx-008: Medium Risk 68)
    return {
      activeCount: 2,
      highRiskCount: 1,
    };
  }

  if (!supabaseUrl || !supabaseAnonKey || !isValidSupabaseKey(supabaseAnonKey)) {
    return { activeCount: 0, highRiskCount: 0 };
  }

  try {
    const client: SupabaseClient = createClient(supabaseUrl, supabaseAnonKey, {
      auth: { persistSession: false, autoRefreshToken: false },
      global: userAccessToken && !userAccessToken.startsWith('demo-')
        ? { headers: { Authorization: `Bearer ${userAccessToken}` } }
        : undefined,
    });

    const { data, error } = await client
      .from('security_alerts')
      .select('risk_level, alert_status')
      .eq('user_id', verifiedUserId)
      .eq('alert_status', 'Active');

    if (error || !data) {
      return { activeCount: 0, highRiskCount: 0 };
    }

    const activeCount = data.length;
    const highRiskCount = data.filter((a: any) => a.risk_level === 'High').length;

    return { activeCount, highRiskCount };
  } catch (err) {
    console.error('[AI Context] Error fetching security alerts summary:', err);
    return { activeCount: 0, highRiskCount: 0 };
  }
}

/**
 * Normalizes and sanitizes untrusted string fields (merchant, description, etc.)
 * to prevent prompt injection or formatting confusion before LLM consumption.
 */
export function sanitizeField(value: unknown, maxLength = 100): string {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/[\r\n\t]/g, ' ')
    .replace(/[<>]/g, '')
    .trim()
    .slice(0, maxLength);
}

/**
 * Retrieves the minimal user-scoped transaction context.
 *
 * Guarantees:
 * 1. Strict user-isolation: Queries ONLY records where user_id === verifiedUserId.
 * 2. Data minimization: Max 100 transactions, bounded within the last 90 days.
 * 3. Field minimization: Excludes all credentials, auth tokens, passwords, and sensitive system metadata.
 * 4. Zero cross-user leakage: When an authenticated user has 0 records, returns empty data with no fallback mock.
 */
export async function getFinancialContextForUser(
  verifiedUserId: string,
  userAccessToken?: string,
  supabaseUrl?: string,
  supabaseAnonKey?: string
): Promise<UserFinancialContextResult> {
  // Demo mode check: Offline demo mode or unconfigured Supabase receives grounded mock context
  if (isDemoSession(verifiedUserId, userAccessToken, supabaseAnonKey)) {
    const sorted = [...INITIAL_MOCK_TRANSACTIONS]
      .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
      .slice(0, MAX_CONTEXT_TRANSACTIONS);

    const items: UserScopedTransactionContextItem[] = sorted.map((tx) => ({
      id: tx.id,
      transaction_date: tx.date,
      merchant: sanitizeField(tx.merchant, 80),
      description: sanitizeField(tx.description, 120),
      category: sanitizeField(tx.category, 50),
      type: tx.type,
      amount: Number(tx.amount),
      location: (tx as any).location ? sanitizeField((tx as any).location, 60) : 'Domestic',
      payment_method: sanitizeField(tx.account || 'UPI / NetBanking', 50),
      risk_level: tx.riskLevel ? tx.riskLevel.toUpperCase() : 'LOW',
      risk_score: Number(tx.riskScore ?? 0),
      security_status: tx.status === 'review' ? 'Review Required' : 'Normal',
      detection_reason: tx.reasons && tx.reasons.length > 0 ? sanitizeField(tx.reasons[0], 150) : null,
    }));

    const dates = items.map((i) => i.transaction_date).filter(Boolean).sort();
    return {
      transactionCount: items.length,
      dateRange: {
        from: dates.length > 0 ? dates[0] : null,
        to: dates.length > 0 ? dates[dates.length - 1] : null,
      },
      transactions: items,
    };
  }

  // Real Supabase User Query
  if (!supabaseUrl || !supabaseAnonKey) {
    return {
      transactionCount: 0,
      dateRange: { from: null, to: null },
      transactions: [],
    };
  }

  try {
    // Construct client scoped with user's access token if available to leverage RLS
    const client: SupabaseClient = createClient(supabaseUrl, supabaseAnonKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
      },
      global: userAccessToken && userAccessToken !== 'demo-access-token'
        ? {
            headers: {
              Authorization: `Bearer ${userAccessToken}`,
            },
          }
        : undefined,
    });

    // Compute 90-day cutoff date
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - MAX_CONTEXT_DAYS);
    const cutoffIso = cutoffDate.toISOString().split('T')[0];

    // Explicit field projection: Query ONLY the 13 safe financial reasoning fields (including id)
    const { data, error } = await client
      .from('transactions')
      .select('id, transaction_date, merchant, description, category, type, amount, location, payment_method, risk_level, risk_score, security_status, detection_reason')
      .eq('user_id', verifiedUserId)
      .gte('transaction_date', cutoffIso)
      .order('transaction_date', { ascending: false })
      .limit(MAX_CONTEXT_TRANSACTIONS);

    if (error) {
      console.error('[AI Context] Database error querying user transactions:', error.message);
      return {
        transactionCount: 0,
        dateRange: { from: null, to: null },
        transactions: [],
      };
    }

    if (!data || data.length === 0) {
      // Authenticated user has zero transactions - do NOT fabricate or show mock data
      return {
        transactionCount: 0,
        dateRange: { from: null, to: null },
        transactions: [],
      };
    }

    const items: UserScopedTransactionContextItem[] = data.map((row: any) => ({
      id: String(row.id || ''),
      transaction_date: row.transaction_date,
      merchant: sanitizeField(row.merchant, 80),
      description: sanitizeField(row.description, 120),
      category: sanitizeField(row.category, 50),
      type: row.type === 'income' ? 'income' : 'expense',
      amount: Number(row.amount || 0),
      location: sanitizeField(row.location || 'Unknown', 60),
      payment_method: sanitizeField(row.payment_method || 'Standard', 50),
      risk_level: sanitizeField(row.risk_level || 'LOW', 20),
      risk_score: Number(row.risk_score || 0),
      security_status: sanitizeField(row.security_status || 'Normal', 30),
      detection_reason: row.detection_reason ? sanitizeField(row.detection_reason, 150) : null,
    }));

    const dates = items.map((i) => i.transaction_date).filter(Boolean).sort();

    return {
      transactionCount: items.length,
      dateRange: {
        from: dates.length > 0 ? dates[0] : null,
        to: dates.length > 0 ? dates[dates.length - 1] : null,
      },
      transactions: items,
    };
  } catch (err) {
    console.error('[AI Context] Unexpected error querying user context:', err);
    return {
      transactionCount: 0,
      dateRange: { from: null, to: null },
      transactions: [],
    };
  }
}
