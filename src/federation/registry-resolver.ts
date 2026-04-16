import { checkPathCoverage } from './path-match.js';
import type { TrustResolver } from './resolver.js';
import type { FederationRegistry, TrustResolutionResult, TrustMark } from '../types.js';

export interface FederationRegistryResolverOptions {
  registryUrl?: string;
  ttlMs?: number;
  maxStaleMs?: number;
  errorTtlMs?: number;
  fetchFn?: typeof fetch;
}

interface CacheState {
  registry: FederationRegistry;
  fetchedAt: number;
  etag?: string;
}

const DEFAULT_REGISTRY_URL = 'https://registry.propdata.org.uk/v1/federation';

export class FederationRegistryResolver implements TrustResolver {
  private cache: CacheState | null = null;
  private readonly registryUrl: string;
  private readonly ttlMs: number;
  private readonly maxStaleMs: number;
  private readonly fetchFn: typeof fetch;

  constructor(options: FederationRegistryResolverOptions = {}) {
    this.registryUrl = options.registryUrl ?? DEFAULT_REGISTRY_URL;
    this.ttlMs = options.ttlMs ?? 3_600_000;
    this.maxStaleMs = options.maxStaleMs ?? 86_400_000;
    this.fetchFn = options.fetchFn ?? globalThis.fetch;
  }

  async resolveTrust(issuerDid: string, credentialPaths?: string[], _trustAnchorDid?: string): Promise<TrustResolutionResult> {
    const registry = await this.getRegistry();
    const paths = credentialPaths ?? [];

    let foundSlug: string | undefined;
    let foundEntry: FederationRegistry['issuers'][string] | undefined;

    for (const [slug, entry] of Object.entries(registry.issuers)) {
      if (entry.did === issuerDid) {
        foundSlug = slug;
        foundEntry = entry;
        break;
      }
    }

    if (!foundEntry) {
      return {
        trusted: false,
        pathsCovered: [],
        uncoveredPaths: paths,
        warnings: [`Issuer DID not found in federation registry: ${issuerDid}`],
      };
    }

    const { slug, entry } = { slug: foundSlug!, entry: foundEntry };
    const warnings: string[] = [];

    const trustMark: TrustMark = {
      trustLevel: entry.trustLevel,
      status: entry.status,
      authorisedPaths: entry.authorisedPaths,
    };

    if (entry.status === 'revoked') {
      return {
        trusted: false,
        issuerSlug: slug,
        trustLevel: entry.trustLevel,
        status: entry.status,
        pathsCovered: [],
        uncoveredPaths: paths,
        warnings: [`Issuer ${slug} is revoked`],
        trustMark,
      };
    }

    if (entry.status === 'deprecated') {
      warnings.push(`Issuer ${slug} is deprecated — credentials may stop being issued`);
    }

    if (entry.status === 'planned') {
      return {
        trusted: false,
        issuerSlug: slug,
        trustLevel: entry.trustLevel,
        status: entry.status,
        pathsCovered: [],
        uncoveredPaths: paths,
        warnings: [`Issuer ${slug} is planned but not yet active`],
        trustMark,
      };
    }

    const now = new Date().toISOString();
    if (entry.validFrom && now < entry.validFrom) {
      warnings.push(`Issuer ${slug} validity period has not started yet`);
    }
    if (entry.validUntil && now > entry.validUntil) {
      return {
        trusted: false,
        issuerSlug: slug,
        trustLevel: entry.trustLevel,
        status: entry.status,
        pathsCovered: [],
        uncoveredPaths: paths,
        warnings: [`Issuer ${slug} validity period has expired`],
        trustMark,
      };
    }

    const { covered, uncovered } = checkPathCoverage(entry.authorisedPaths, paths);

    if (uncovered.length > 0) {
      warnings.push(`Issuer ${slug} not authorised for paths: ${uncovered.join(', ')}`);
    }

    return {
      trusted: uncovered.length === 0,
      issuerSlug: slug,
      trustLevel: entry.trustLevel,
      status: entry.status,
      pathsCovered: covered,
      uncoveredPaths: uncovered,
      warnings,
      trustMark,
    };
  }

  private async getRegistry(): Promise<FederationRegistry> {
    if (this.cache && Date.now() - this.cache.fetchedAt < this.ttlMs) {
      return this.cache.registry;
    }

    try {
      const registry = await this.fetchRegistry();
      return registry;
    } catch (err) {
      if (this.cache && Date.now() - this.cache.fetchedAt < this.maxStaleMs) {
        return this.cache.registry;
      }
      throw err;
    }
  }

  private async fetchRegistry(): Promise<FederationRegistry> {
    const headers: Record<string, string> = { 'Accept': 'application/json' };
    if (this.cache?.etag) {
      headers['If-None-Match'] = this.cache.etag;
    }

    const response = await this.fetchFn(this.registryUrl, {
      headers,
      signal: AbortSignal.timeout(10_000),
    });

    if (response.status === 304 && this.cache) {
      this.cache.fetchedAt = Date.now();
      return this.cache.registry;
    }

    if (!response.ok) {
      throw new Error(`Federation registry fetch failed: HTTP ${response.status}`);
    }

    const registry = await response.json() as FederationRegistry;
    const etag = response.headers.get('etag') ?? undefined;

    this.cache = { registry, fetchedAt: Date.now(), etag };
    return registry;
  }
}
