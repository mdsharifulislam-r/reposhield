/**
 * RepoShield — Result Cache
 *
 * Caches scan results using file content hash + rule engine version.
 * Invalidates when files or rules change.
 * Bounded memory consumption.
 */

import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import os from 'os';
import { FileScanResult } from './analyzer.js';

const CACHE_VERSION = '1'; // Bump this when rule engine changes
const MAX_CACHE_ENTRIES = 5000;

interface CacheEntry {
  contentHash: string;
  ruleVersion: string;
  result: FileScanResult;
  accessedAt: number;
}

// In-memory cache with LRU eviction
const memoryCache = new Map<string, CacheEntry>();

function hashContent(content: string): string {
  return crypto.createHash('sha256').update(content).digest('hex');
}

function getCacheKey(filePath: string): string {
  return crypto.createHash('sha256').update(filePath).digest('hex');
}

export function getCachedResult(
  filePath: string,
  content: string,
  noCache: boolean,
): FileScanResult | null {
  if (noCache) return null;

  const key = getCacheKey(filePath);
  const entry = memoryCache.get(key);
  if (!entry) return null;

  const contentHash = hashContent(content);
  if (entry.contentHash !== contentHash || entry.ruleVersion !== CACHE_VERSION) {
    memoryCache.delete(key);
    return null;
  }

  entry.accessedAt = Date.now();
  return entry.result;
}

export function setCachedResult(
  filePath: string,
  content: string,
  result: FileScanResult,
  noCache: boolean,
): void {
  if (noCache) return;

  // Evict oldest entries if cache is full (simple LRU)
  if (memoryCache.size >= MAX_CACHE_ENTRIES) {
    let oldest: [string, CacheEntry] | null = null;
    for (const [k, v] of memoryCache.entries()) {
      if (!oldest || v.accessedAt < oldest[1].accessedAt) {
        oldest = [k, v];
      }
    }
    if (oldest) memoryCache.delete(oldest[0]);
  }

  const key = getCacheKey(filePath);
  memoryCache.set(key, {
    contentHash: hashContent(content),
    ruleVersion: CACHE_VERSION,
    result,
    accessedAt: Date.now(),
  });
}

export function getCacheStats(): { size: number; version: string } {
  return { size: memoryCache.size, version: CACHE_VERSION };
}

export function clearCache(): void {
  memoryCache.clear();
}
