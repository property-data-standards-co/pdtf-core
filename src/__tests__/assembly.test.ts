import { describe, it, expect } from 'vitest';
import {
  composeV4StateFromGraph,
  composeV3StateFromGraph,
} from '../assembly/index.js';
import type { VerifiableCredential } from '../types.js';

const CTX = [
  'https://www.w3.org/ns/credentials/v2',
  'https://vocab.pdtf.org/credentials/v1',
];

function vc(
  type: string,
  subjectId: string,
  subject: Record<string, any>,
  validFrom = '2026-04-01T00:00:00Z'
): VerifiableCredential {
  return {
    '@context': CTX,
    type: ['VerifiableCredential', `${type}Credential`],
    issuer: 'did:key:z6Mkj',
    validFrom,
    credentialSubject: { id: subjectId, type, ...subject },
  };
}

const propertyId = 'urn:pdtf:uprn:100023336956';
const transactionId = 'urn:uuid:tx-0001';
const titleId = 'urn:pdtf:title:ABC123';
const sellerId = 'urn:pdtf:person:seller-1';
const buyerId = 'urn:pdtf:person:buyer-1';
const conveyancerId = 'urn:pdtf:org:conv-1';

const credentials: VerifiableCredential[] = [
  vc('Property', propertyId, {
    address: { line1: '42 Acacia Avenue', postcode: 'TS1 2AB' },
    uprn: '100023336956',
  }),
  // Later VC merges extra fields into Property
  vc(
    'Property',
    propertyId,
    { address: { line2: 'Testington' }, councilTax: { band: 'C' } },
    '2026-04-10T00:00:00Z'
  ),
  vc('Title', titleId, {
    titleNumber: 'ABC123',
    tenure: 'Freehold',
  }),
  vc('Transaction', transactionId, {
    property: { id: propertyId },
    saleContext: { askingPrice: 500000, status: 'forSale' },
  }),
  vc('Person', sellerId, {
    name: { firstName: 'Alice', lastName: 'Seller' },
  }),
  vc('Person', buyerId, {
    name: { firstName: 'Bob', lastName: 'Buyer' },
  }),
  vc('Organisation', conveyancerId, {
    name: 'Acme Law LLP',
  }),
  vc('SellerCapacity', 'urn:uuid:sc-1', {
    party: { id: sellerId },
    capacity: 'LegalOwner',
    role: 'Seller',
  }),
  vc('Representation', 'urn:uuid:rep-1', {
    represents: { id: sellerId },
    representative: { id: conveyancerId },
    role: 'Conveyancer',
  }),
  vc('Offer', 'urn:uuid:offer-1', {
    buyer: { id: buyerId },
    amount: 495000,
  }),
];

describe('composeV4StateFromGraph', () => {
  it('groups VCs by subject and deep-merges in time order', () => {
    const s = composeV4StateFromGraph(credentials);
    expect(s.properties[propertyId]).toBeDefined();
    expect(s.properties[propertyId].address.line1).toBe('42 Acacia Avenue');
    expect(s.properties[propertyId].address.line2).toBe('Testington');
    expect(s.properties[propertyId].councilTax.band).toBe('C');
    expect(s.titles[titleId].titleNumber).toBe('ABC123');
    expect(s.transactions[transactionId].saleContext.askingPrice).toBe(500000);
    expect(s.persons[sellerId].name.firstName).toBe('Alice');
    expect(s.organisations[conveyancerId].name).toBe('Acme Law LLP');
  });

  it('applies later VCs over earlier ones (sorted by validFrom)', () => {
    const earlier = vc('Property', propertyId, { status: 'old' }, '2026-01-01T00:00:00Z');
    const later = vc('Property', propertyId, { status: 'new' }, '2026-06-01T00:00:00Z');
    const s = composeV4StateFromGraph([later, earlier]);
    expect(s.properties[propertyId].status).toBe('new');
  });

  it('skips credentials with missing subject id', () => {
    const skips: string[] = [];
    const bad = {
      ...vc('Property', 'x', {}),
      credentialSubject: { type: 'Property' } as any,
    };
    composeV4StateFromGraph([bad as any], {
      onSkip: (_vc, reason) => skips.push(reason),
    });
    expect(skips).toContain('missing credentialSubject.id');
  });
});

describe('composeV3StateFromGraph', () => {
  it('maps the v4 graph into the legacy monolithic structure', () => {
    const state = composeV3StateFromGraph(credentials);
    expect(state.id).toBe(transactionId);
    expect(state.propertyPack).toBeDefined();
    expect(state.propertyPack.uprn).toBe('100023336956');
    expect(state.propertyPack.titlesToBeSold).toHaveLength(1);
    expect(state.propertyPack.titlesToBeSold[0].titleNumber).toBe('ABC123');

    // saleContext moved into propertyPack.ownership
    expect(state.propertyPack.ownership.askingPrice).toBe(500000);
    expect(state.propertyPack.ownership.status).toBe('forSale');

    // participants flattened with role + participantType
    const roles = state.participants.map((p: any) => p.role);
    expect(roles).toContain('Seller');
    expect(roles).toContain('Buyer');
    expect(roles).toContain('Conveyancer');

    const conveyancer = state.participants.find(
      (p: any) => p.role === 'Conveyancer'
    );
    expect(conveyancer.participantType).toBe('Organisation');
    expect(conveyancer.name).toBe('Acme Law LLP');
    expect(conveyancer.represents).toBe(sellerId);

    const buyer = state.participants.find((p: any) => p.role === 'Buyer');
    expect(buyer.participantType).toBe('Person');
    expect(buyer.offerAmount).toBe(495000);

    const seller = state.participants.find((p: any) => p.role === 'Seller');
    expect(seller.capacity).toBe('LegalOwner');
  });

  it('handles empty input gracefully', () => {
    const state = composeV3StateFromGraph([]);
    expect(state.propertyPack).toBeDefined();
    expect(state.propertyPack.titlesToBeSold).toEqual([]);
    expect(state.participants).toEqual([]);
  });
});
