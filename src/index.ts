import { createHash } from 'node:crypto';
import {
	type Item,
	isInnerList,
	parseDictionary,
	serializeDictionary,
} from 'structured-headers';

export type DigestAlgorithm = 'sha-256' | 'sha-512';

/**
 * Implementation of functions to assist with HTTP Content Digest headers per
 * https://www.ietf.org/archive/id/draft-ietf-httpbis-digest-headers-10.txt
 *
 * Supported algorithms
 *
 * +===========+==========+============================+==============+
 * | Algorithm | Status   | Description                | Reference(s) |
 * | Key       |          |                            |              |
 * +===========+==========+============================+==============+
 * | sha-512   | standard | The SHA-512 algorithm.     | [RFC6234],   |
 * |           |          |                            | [RFC4648]    |
 * +-----------+----------+----------------------------+--------------+
 * | sha-256   | standard | The SHA-256 algorithm.     | [RFC6234],   |
 * |           |          |                            | [RFC4648]    |
 * +-----------+----------+----------------------------+--------------+
 *
 */

/**
 * Returns the nodejs hash digest algorithm identifier given an identifier from a content-digest header
 *
 * @param algorithm the algorithm identifier as specified in the header
 * @returns the algorithm identifier to use in the nodejs `createHash` function
 */
function nodeAlgo(algorithm: string): string {
	switch (algorithm) {
		case 'sha-256':
			return 'sha256';
		case 'sha-512':
			return 'sha512';
		default:
			throw new Error(`Unsupported digest algorithm '${algorithm}'.`);
	}
}

/**
 * Create the content-digest header for a given message body
 *
 * @param body the message body
 * @param algorithms the digest algorithms to use (only 'sha-256' and 'sha-512' supported)
 * @returns the string that can be used as the content-digest header value
 */
export function createContentDigestHeader(
	body: string | Buffer | undefined,
	algorithms: DigestAlgorithm[],
): string {
	return serializeDictionary(
		new Map<string, Item>(
			algorithms.map((algo) => {
				return [
					algo,
					[toArrayBuffer(hashBody(body, algo)), new Map()],
				] as readonly [string, Item];
			}),
		),
	);
}

/**
 * Verify a content-digest header against a message body
 *
 * @param body the message body
 * @param digestHeader the content-digest header
 * @returns true if all digests in the header are verified, false if not
 */
export function verifyContentDigest(
	body: string | Buffer | undefined,
	digestHeader: string,
) {
	const digests = parseDictionary(digestHeader);
	for (const [algo, digest] of digests) {
		if (isInnerList(digest) || !(digest[0] instanceof ArrayBuffer)) {
			throw new Error(
				`Invalid value for digest with algorithm key of '${algo}'`,
			);
		}
		const hash = hashBody(body, algo);
		if (!hash.equals(Buffer.from(digest[0]))) {
			return false;
		}
	}
	return true;
}

function hashBody(body: string | Buffer | undefined, algo: string): Buffer {
	return createHash(nodeAlgo(algo))
		.update(body || '')
		.digest();
}

function toArrayBuffer(buffer: Buffer): ArrayBuffer {
	return buffer.buffer.slice(
		buffer.byteOffset,
		buffer.byteOffset + buffer.byteLength,
	);
}
