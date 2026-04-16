/**
 * State Assembly
 *
 * Composes PDTF state from a bundle of Verifiable Credentials.
 *
 * - `composeV4StateFromGraph` groups VCs by `credentialSubject.id`, sorts by
 *   issuance time, and deep-merges the `credentialSubject` properties into
 *   an entity dictionary keyed by URN and grouped by entity type.
 *
 * - `composeV3StateFromGraph` maps the v4 entity graph back into the legacy
 *   v3 `pdtf-transaction.json` monolithic structure for backward compat.
 */

import type { VerifiableCredential, CredentialSubject } from '../types.js';

export interface AssemblyOptions {
  /** Entity types to include. Defaults to all. */
  includeTypes?: string[];
  /** Callback fired when a VC is skipped (missing subject id, etc.) */
  onSkip?: (vc: VerifiableCredential, reason: string) => void;
}

// ─── Entity type classification ─────────────────────────────────────────────

/**
 * Classification of entity types by the VC `type[]` or
 * `credentialSubject.type`. Maps an entity-type label to the plural bucket
 * used in the v4 graph output.
 */
const ENTITY_TYPE_BUCKETS: Record<string, string> = {
  Property: 'properties',
  Transaction: 'transactions',
  Title: 'titles',
  Person: 'persons',
  Organisation: 'organisations',
  Organization: 'organisations',
  Representation: 'representations',
  SellerCapacity: 'sellerCapacities',
  Ownership: 'sellerCapacities',
  DelegatedConsent: 'delegatedConsents',
  Offer: 'offers',
};

/**
 * Derive the entity type of a VC by preferring `credentialSubject.type`
 * (a single string) and falling back to any `type[]` entry whose suffix
 * matches a known entity bucket.
 */
function getEntityType(vc: VerifiableCredential): string | undefined {
  const cs = vc.credentialSubject;
  if (cs && typeof cs.type === 'string' && ENTITY_TYPE_BUCKETS[cs.type]) {
    return cs.type;
  }
  for (const t of vc.type ?? []) {
    // Accept "PropertyCredential" or "Property"
    const base = t.endsWith('Credential') ? t.slice(0, -'Credential'.length) : t;
    if (ENTITY_TYPE_BUCKETS[base]) return base;
  }
  // Subject type may be any other string (e.g. EPC) — treat as Property facet
  if (cs && typeof cs.type === 'string') return cs.type;
  return undefined;
}

function bucketFor(entityType: string): string {
  return ENTITY_TYPE_BUCKETS[entityType] ?? `${entityType.toLowerCase()}s`;
}

// ─── Deep merge ─────────────────────────────────────────────────────────────

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** Deep merge `src` into `dst`. Arrays are replaced, not concatenated. */
function deepMerge(
  dst: Record<string, unknown>,
  src: Record<string, unknown>
): Record<string, unknown> {
  for (const [k, v] of Object.entries(src)) {
    const existing = dst[k];
    if (isPlainObject(existing) && isPlainObject(v)) {
      dst[k] = deepMerge({ ...existing }, v);
    } else {
      dst[k] = v;
    }
  }
  return dst;
}

// ─── v4 graph composition ──────────────────────────────────────────────────

export interface V4State {
  properties: Record<string, any>;
  transactions: Record<string, any>;
  titles: Record<string, any>;
  persons: Record<string, any>;
  organisations: Record<string, any>;
  representations: Record<string, any>;
  sellerCapacities: Record<string, any>;
  delegatedConsents: Record<string, any>;
  offers: Record<string, any>;
  [bucket: string]: Record<string, any>;
}

function emptyV4State(): V4State {
  return {
    properties: {},
    transactions: {},
    titles: {},
    persons: {},
    organisations: {},
    representations: {},
    sellerCapacities: {},
    delegatedConsents: {},
    offers: {},
  };
}

/**
 * Compose a v4 entity-graph state from a bundle of VCs.
 *
 * VCs are grouped by `credentialSubject.id` and sorted ascending by
 * `validFrom` (falling back to `issuanceDate` or a zero epoch). The
 * `credentialSubject` of each VC is then deep-merged in order so later
 * credentials override earlier ones, producing one canonical entity per URN.
 */
export function composeV4StateFromGraph(
  credentials: VerifiableCredential[],
  options: AssemblyOptions = {}
): V4State {
  const state = emptyV4State();
  const { onSkip } = options;

  // Group by subject id
  const groups = new Map<string, VerifiableCredential[]>();
  for (const vc of credentials) {
    const id = vc.credentialSubject?.id;
    if (!id) {
      onSkip?.(vc, 'missing credentialSubject.id');
      continue;
    }
    const existing = groups.get(id);
    if (existing) existing.push(vc);
    else groups.set(id, [vc]);
  }

  for (const [subjectId, vcs] of groups) {
    // Sort ascending by validFrom / issuanceDate
    vcs.sort((a, b) => {
      const ta = Date.parse(a.validFrom ?? (a as any).issuanceDate ?? '') || 0;
      const tb = Date.parse(b.validFrom ?? (b as any).issuanceDate ?? '') || 0;
      return ta - tb;
    });

    // Determine entity type from the first typed VC in the group
    let entityType: string | undefined;
    for (const vc of vcs) {
      const t = getEntityType(vc);
      if (t && ENTITY_TYPE_BUCKETS[t]) {
        entityType = t;
        break;
      }
    }
    if (!entityType) {
      // Fall back to whatever we can read from subject.type
      entityType =
        (typeof vcs[0].credentialSubject.type === 'string'
          ? (vcs[0].credentialSubject.type as string)
          : undefined) ?? 'Unknown';
    }

    if (options.includeTypes && !options.includeTypes.includes(entityType)) continue;

    const bucket = bucketFor(entityType);
    if (!state[bucket]) state[bucket] = {};

    const merged: Record<string, unknown> = state[bucket][subjectId]
      ? { ...state[bucket][subjectId] }
      : { id: subjectId };

    for (const vc of vcs) {
      const { id: _id, ...rest } = vc.credentialSubject as CredentialSubject &
        Record<string, unknown>;
      deepMerge(merged, rest);
    }
    merged.id = subjectId;
    state[bucket][subjectId] = merged;
  }

  return state;
}

// ─── v3 legacy mapping ─────────────────────────────────────────────────────

/**
 * Map a v4 entity graph back into the legacy v3 `pdtf-transaction.json`
 * monolithic shape used by older clients and the existing PDTF state schema.
 *
 * The mapping is best-effort and intentionally forgiving: unknown fields are
 * preserved in their original buckets so downstream consumers can still reach
 * them via `v4` escape hatches if needed.
 */
export function composeV3StateFromGraph(
  credentials: VerifiableCredential[],
  options: AssemblyOptions = {}
): Record<string, any> {
  const v4 = composeV4StateFromGraph(credentials, options);

  // Pick the single transaction (if any) as the root.
  const transactionEntries = Object.entries(v4.transactions);
  const [transactionId, transaction] = transactionEntries[0] ?? [undefined, {}];

  // Extract saleContext from the transaction and move to propertyPack.ownership
  const {
    saleContext,
    property: txProperty, // optional link
    ...transactionRest
  } = (transaction as Record<string, any>) ?? {};

  // Single Property → root propertyPack
  const properties = Object.values(v4.properties) as Record<string, any>[];
  const property = properties[0] ?? {};

  const propertyPack: Record<string, any> = {
    ...property,
    titlesToBeSold: Object.values(v4.titles),
  };

  if (saleContext) {
    propertyPack.ownership = {
      ...(propertyPack.ownership ?? {}),
      ...saleContext,
    };
  }

  // Build flat participants[] from Persons/Orgs + Representation/SellerCapacity/Offer
  const personsById = v4.persons;
  const orgsById = v4.organisations;

  const participants: Record<string, any>[] = [];
  const seen = new Set<string>();

  const pushParticipant = (
    subjectId: string,
    role: string,
    participantType: 'Person' | 'Organisation',
    extra?: Record<string, any>
  ) => {
    const base =
      participantType === 'Person'
        ? personsById[subjectId]
        : orgsById[subjectId];
    if (!base) return;
    const key = `${subjectId}::${role}`;
    if (seen.has(key)) return;
    seen.add(key);
    participants.push({
      ...base,
      role,
      participantType,
      ...(extra ?? {}),
    });
  };

  // Representation: { represents: <personOrOrg>, representative: <org|person>, role: "Conveyancer"|... }
  for (const rep of Object.values(v4.representations) as Record<string, any>[]) {
    const role = rep.role ?? rep.representativeRole ?? 'Representative';
    const representativeId =
      rep.representative?.id ?? rep.representativeId ?? rep.representative;
    if (typeof representativeId === 'string') {
      const pt = orgsById[representativeId] ? 'Organisation' : 'Person';
      pushParticipant(representativeId, role, pt, {
        represents: rep.represents?.id ?? rep.representsId ?? rep.represents,
      });
    }
  }

  // SellerCapacity: a Person/Org is a Seller (legal owner / capacity)
  for (const sc of Object.values(v4.sellerCapacities) as Record<string, any>[]) {
    const role = sc.role ?? 'Seller';
    const partyId = sc.party?.id ?? sc.partyId ?? sc.party ?? sc.owner;
    if (typeof partyId === 'string') {
      const pt = personsById[partyId] ? 'Person' : 'Organisation';
      pushParticipant(partyId, role, pt, {
        capacity: sc.capacity,
      });
    }
  }

  // Offer: a Person/Org is a Buyer
  for (const offer of Object.values(v4.offers) as Record<string, any>[]) {
    const role = 'Buyer';
    const buyerId = offer.buyer?.id ?? offer.buyerId ?? offer.buyer;
    if (typeof buyerId === 'string') {
      const pt = personsById[buyerId] ? 'Person' : 'Organisation';
      pushParticipant(buyerId, role, pt, {
        offerAmount: offer.amount ?? offer.offerAmount,
      });
    }
  }

  const state: Record<string, any> = {
    ...(transactionId ? { id: transactionId } : {}),
    ...transactionRest,
    propertyPack,
    participants,
  };

  return state;
}
