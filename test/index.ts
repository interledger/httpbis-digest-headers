import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
	createContentDigestHeader,
	type DigestAlgorithm,
	verifyContentDigest,
} from '../src/index.ts';

const throwsMessage = (pattern: RegExp) => (err: unknown) =>
	err instanceof Error && pattern.test(err.message);

describe('digest', () => {
	describe('.createContentDigestHeader', () => {
		it('creates a single digest from an empty body (SHA256)', () => {
			const test = undefined;
			const digest = createContentDigestHeader(test, ['sha-256']);
			assert.equal(
				digest,
				'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:',
			);
		});
		it('creates a single digest from an empty body (SHA512)', () => {
			const test = undefined;
			const digest = createContentDigestHeader(test, ['sha-512']);
			assert.equal(
				digest,
				'sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:',
			);
		});
		it('creates a single digest from a body (SHA256)', () => {
			const test = '{hello:"world"}';
			const digest = createContentDigestHeader(test, ['sha-256']);
			assert.equal(
				digest,
				'sha-256=:LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs=:',
			);
		});
		it('creates a single digest from a body (SHA512)', () => {
			const test = '{hello:"world"}';
			const digest = createContentDigestHeader(test, ['sha-512']);
			assert.equal(
				digest,
				'sha-512=:YwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:',
			);
		});
		it('creates multiple digests from empty body', () => {
			const test = undefined;
			const digest = createContentDigestHeader(test, ['sha-256', 'sha-512']);
			assert.equal(
				digest,
				'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:, sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:',
			);
			return;
		});
		it('creates multiple digests from a body', () => {
			const test = '{hello:"world"}';
			const digest = createContentDigestHeader(test, ['sha-256', 'sha-512']);
			assert.equal(
				digest,
				'sha-256=:LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs=:, sha-512=:YwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:',
			);
			return;
		});
		it('throws  with invalid digest algorithm', () => {
			assert.throws(
				createContentDigestHeader.bind(undefined, '', [
					'nonsense' as DigestAlgorithm,
				]),
				throwsMessage(/^Unsupported digest algorithm/),
			);
		});
	});

	describe('.verifyContentDigest', () => {
		it('verifies a single digest (SHA256)', () => {
			assert.equal(
				verifyContentDigest(
					'{hello:"world"}',
					'sha-256=:LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs=:',
				),
				true,
			);
		});
		it('verifies a single digest with empty body (SHA256)', () => {
			assert.equal(
				verifyContentDigest(
					undefined,
					'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:',
				),
				true,
			);
		});
		it('verifies a single digest (SHA512)', () => {
			assert.equal(
				verifyContentDigest(
					'{hello:"world"}',
					'sha-512=:YwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:',
				),
				true,
			);
		});
		it("doesn't verify a single invalid digest (SHA256)", () => {
			assert.equal(
				verifyContentDigest(
					'{goodbye:"world"}',
					'sha-256=:LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs=:',
				),
				false,
			);
		});
		it("doesn't verify a single invalid digest (SHA512)", () => {
			assert.equal(
				verifyContentDigest(
					'{goodbye:"world"}',
					'sha-512=:YwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:',
				),
				false,
			);
		});
		it('throws with invalid digest algorithm', () => {
			assert.throws(
				verifyContentDigest.bind(
					undefined,
					'{hello:"world"}',
					'md5=:YwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:',
				),
				throwsMessage(/^Unsupported digest algorithm/),
			);
		});
		it('throws with invalid header', () => {
			assert.throws(
				verifyContentDigest.bind(undefined, '', 'sha-256="NOT A HASH"'),
				throwsMessage(/^Invalid value for digest/),
			);
			assert.throws(
				verifyContentDigest.bind(
					undefined,
					'',
					'sha-256=LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs=',
				),
				throwsMessage(/^Parse error/),
			);
		});
		it('verifies two digests (SHA256 and SHA512)', () => {
			assert.equal(
				verifyContentDigest(
					'{hello:"world"}',
					'sha-256=:LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs=:, sha-512=:YwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:',
				),
				true,
			);
		});
		it('verifies two digests (SHA256 and SHA512) in any order', () => {
			assert.equal(
				verifyContentDigest(
					'{hello:"world"}',
					'sha-512=:YwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:, sha-256=:LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs=:',
				),
				true,
			);
		});
		it("doesn't verify if any digest fails", () => {
			assert.equal(
				verifyContentDigest(
					'{hello:"world"}',
					'sha-512=:ZwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:, sha-256=:LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs=:',
				),
				false,
			);
		});
	});
});
