// OpenSpective — Cryptocurrency & Blockchain Wallet OSINT Collector
// Passive analysis of blockchain addresses (Bitcoin, Ethereum, Solana, TRON).
// Connects to open block explorers with no authentication required.

export interface CryptoWalletResults {
  address: string;
  network: 'bitcoin' | 'ethereum' | 'solana' | 'tron' | 'unknown';
  isValid: boolean;
  balanceFormatted: string | null;
  totalReceivedFormatted: string | null;
  totalSentFormatted: string | null;
  transactionCount: number | null;
  firstActivity: string | null;
  lastActivity: string | null;
  explorerUrl: string;
  source: string;
  collectedAt: string;
  error?: string;
}

export function detectCryptoNetwork(address: string): 'bitcoin' | 'ethereum' | 'solana' | 'tron' | 'unknown' {
  const trimmed = address.trim();
  if (/^(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})$/i.test(trimmed)) {
    return 'bitcoin';
  }
  if (/^0x[a-fA-F0-9]{40}$/.test(trimmed)) {
    return 'ethereum';
  }
  if (/^T[a-km-zA-HJ-NP-Z1-9]{33}$/.test(trimmed)) {
    return 'tron';
  }
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(trimmed)) {
    return 'solana';
  }
  return 'unknown';
}

export async function collectCryptoWallet(address: string): Promise<CryptoWalletResults> {
  const collectedAt = new Date().toISOString();
  const trimmed = address.trim();
  const network = detectCryptoNetwork(trimmed);

  if (network === 'bitcoin') {
    return collectBitcoinWallet(trimmed, collectedAt);
  } else if (network === 'ethereum') {
    return collectEthereumWallet(trimmed, collectedAt);
  } else if (network === 'solana') {
    return {
      address: trimmed,
      network: 'solana',
      isValid: true,
      balanceFormatted: null,
      totalReceivedFormatted: null,
      totalSentFormatted: null,
      transactionCount: null,
      firstActivity: null,
      lastActivity: null,
      explorerUrl: `https://solscan.io/account/${trimmed}`,
      source: 'Solana Public Explorer',
      collectedAt,
    };
  } else if (network === 'tron') {
    return {
      address: trimmed,
      network: 'tron',
      isValid: true,
      balanceFormatted: null,
      totalReceivedFormatted: null,
      totalSentFormatted: null,
      transactionCount: null,
      firstActivity: null,
      lastActivity: null,
      explorerUrl: `https://tronscan.org/#/address/${trimmed}`,
      source: 'TronScan Public Explorer',
      collectedAt,
    };
  }

  return {
    address: trimmed,
    network: 'unknown',
    isValid: false,
    balanceFormatted: null,
    totalReceivedFormatted: null,
    totalSentFormatted: null,
    transactionCount: null,
    firstActivity: null,
    lastActivity: null,
    explorerUrl: `https://www.blockchain.com/explorer/search?search=${trimmed}`,
    source: 'Blockchain Analyzer',
    collectedAt,
    error: 'Unrecognized cryptocurrency address format.',
  };
}

async function collectBitcoinWallet(address: string, collectedAt: string): Promise<CryptoWalletResults> {
  const explorerUrl = `https://www.blockchain.com/explorer/addresses/btc/${address}`;
  try {
    const url = `https://blockchain.info/rawaddr/${encodeURIComponent(address)}?limit=5`;
    const resp = await fetch(url, {
      signal: AbortSignal.timeout(8000),
      headers: {
        'User-Agent': 'OpenSpective/0.1 (Research)',
        Accept: 'application/json',
      },
    });

    if (!resp.ok) {
      // Fallback: blockstream info
      return collectBitcoinBlockstream(address, collectedAt);
    }

    const data = await resp.json() as {
      final_balance?: number;
      n_tx?: number;
      total_received?: number;
      total_sent?: number;
      txs?: Array<{ time?: number }>;
    };

    const satoshiToBtc = (sat: number) => (sat / 1e8).toFixed(8) + ' BTC';
    const txTimes = (data.txs ?? []).map(t => t.time).filter((t): t is number => Boolean(t));
    const firstActivity = txTimes.length ? new Date(Math.min(...txTimes) * 1000).toISOString() : null;
    const lastActivity = txTimes.length ? new Date(Math.max(...txTimes) * 1000).toISOString() : null;

    return {
      address,
      network: 'bitcoin',
      isValid: true,
      balanceFormatted: data.final_balance != null ? satoshiToBtc(data.final_balance) : '0 BTC',
      totalReceivedFormatted: data.total_received != null ? satoshiToBtc(data.total_received) : null,
      totalSentFormatted: data.total_sent != null ? satoshiToBtc(data.total_sent) : null,
      transactionCount: data.n_tx ?? 0,
      firstActivity,
      lastActivity,
      explorerUrl,
      source: 'Blockchain.info Public API',
      collectedAt,
    };
  } catch {
    return collectBitcoinBlockstream(address, collectedAt);
  }
}

async function collectBitcoinBlockstream(address: string, collectedAt: string): Promise<CryptoWalletResults> {
  const explorerUrl = `https://blockstream.info/address/${address}`;
  try {
    const url = `https://blockstream.info/api/address/${encodeURIComponent(address)}`;
    const resp = await fetch(url, { signal: AbortSignal.timeout(8000) });
    if (!resp.ok) {
      return {
        address,
        network: 'bitcoin',
        isValid: true,
        balanceFormatted: null,
        totalReceivedFormatted: null,
        totalSentFormatted: null,
        transactionCount: null,
        firstActivity: null,
        lastActivity: null,
        explorerUrl,
        source: 'Blockstream Explorer',
        collectedAt,
      };
    }

    const data = await resp.json() as {
      chain_stats?: {
        funded_txo_count?: number;
        spent_txo_count?: number;
        funded_txo_sum?: number;
        spent_txo_sum?: number;
        tx_count?: number;
      };
    };

    const stats = data.chain_stats ?? {};
    const funded = stats.funded_txo_sum ?? 0;
    const spent = stats.spent_txo_sum ?? 0;
    const balance = funded - spent;
    const satoshiToBtc = (sat: number) => (sat / 1e8).toFixed(8) + ' BTC';

    return {
      address,
      network: 'bitcoin',
      isValid: true,
      balanceFormatted: satoshiToBtc(balance),
      totalReceivedFormatted: satoshiToBtc(funded),
      totalSentFormatted: satoshiToBtc(spent),
      transactionCount: stats.tx_count ?? 0,
      firstActivity: null,
      lastActivity: null,
      explorerUrl,
      source: 'Blockstream Public API',
      collectedAt,
    };
  } catch (err) {
    return {
      address,
      network: 'bitcoin',
      isValid: true,
      balanceFormatted: null,
      totalReceivedFormatted: null,
      totalSentFormatted: null,
      transactionCount: null,
      firstActivity: null,
      lastActivity: null,
      explorerUrl,
      source: 'Blockstream Explorer',
      collectedAt,
      error: err instanceof Error ? err.message : 'Lookup failed',
    };
  }
}

async function collectEthereumWallet(address: string, collectedAt: string): Promise<CryptoWalletResults> {
  const explorerUrl = `https://etherscan.io/address/${address}`;
  try {
    // Blockscout free public API for Ethereum mainnet
    const url = `https://eth.blockscout.com/api/v2/addresses/${encodeURIComponent(address)}`;
    const resp = await fetch(url, {
      signal: AbortSignal.timeout(8000),
      headers: { Accept: 'application/json' },
    });

    if (!resp.ok) {
      return {
        address,
        network: 'ethereum',
        isValid: true,
        balanceFormatted: null,
        totalReceivedFormatted: null,
        totalSentFormatted: null,
        transactionCount: null,
        firstActivity: null,
        lastActivity: null,
        explorerUrl,
        source: 'Etherscan',
        collectedAt,
      };
    }

    const data = await resp.json() as {
      coin_balance?: string;
      exchange_rate?: string;
      is_contract?: boolean;
    };

    let balanceFormatted: string | null = null;
    if (data.coin_balance) {
      const wei = BigInt(data.coin_balance);
      const eth = Number(wei) / 1e18;
      balanceFormatted = `${eth.toFixed(4)} ETH`;
    }

    return {
      address,
      network: 'ethereum',
      isValid: true,
      balanceFormatted,
      totalReceivedFormatted: null,
      totalSentFormatted: null,
      transactionCount: null,
      firstActivity: null,
      lastActivity: null,
      explorerUrl,
      source: 'Blockscout Ethereum Indexer',
      collectedAt,
    };
  } catch {
    return {
      address,
      network: 'ethereum',
      isValid: true,
      balanceFormatted: null,
      totalReceivedFormatted: null,
      totalSentFormatted: null,
      transactionCount: null,
      firstActivity: null,
      lastActivity: null,
      explorerUrl,
      source: 'Etherscan',
      collectedAt,
    };
  }
}
