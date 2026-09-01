import {
	type Item,
	isInnerList,
	parseDictionary,
	serializeDictionary,
} from 'structured-headers';

/**
 * The digest algorithms supported. Content-Digest header keys use the
 * lowercased form of these identifiers.
 */
export type DigestAlgorithm = 'SHA-256' | 'SHA-512';

/**
 * A string or any binary source `crypto.subtle.digest` understands, so this
 * works in both Node.js and browser environments.
 */
export type DigestBody = string | BufferSource;

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
 * | SHA-512   | standard | The SHA-512 algorithm.     | [RFC6234],   |
 * |           |          |                            | [RFC4648]    |
 * +-----------+----------+----------------------------+--------------+
 * | SHA-256   | standard | The SHA-256 algorithm.     | [RFC6234],   |
 * |           |          |                            | [RFC4648]    |
 * +-----------+----------+----------------------------+--------------+
 *
 */

/**
 * Create the content-digest header for a given message body
 *
 * @param body the message body
 * @param algorithms the digest algorithms to use (only 'SHA-256' and 'SHA-512' supported)
 * @returns the string that can be used as the content-digest header value
 */
export async function createContentDigestHeader(
	body: DigestBody,
	algorithms: DigestAlgorithm[],
): Promise<string> {
	const entries = await Promise.all(
		algorithms.map(async (algo) => {
			const digest = await hashBody(body, toDigestAlgorithm(algo));
			const key = algo.toLowerCase();
			return [key, [digest, new Map()]] as readonly [string, Item];
		}),
	);
	return serializeDictionary(new Map(entries));
}

/**
 * Verify a content-digest header against a message body
 *
 * @param body the message body
 * @param digestHeader the content-digest header
 * @returns true if all digests in the header are verified, false if not
 */
export async function verifyContentDigest(
	body: DigestBody,
	digestHeader: string,
): Promise<boolean> {
	const digests = parseDictionary(digestHeader);
	for (const [algo, digest] of digests) {
		if (isInnerList(digest) || !(digest[0] instanceof ArrayBuffer)) {
			throw new Error(
				`Invalid value for digest with algorithm key of '${algo}'`,
			);
		}
		const hash = await hashBody(body, toDigestAlgorithm(algo));
		if (!arrayBuffersEqual(hash, digest[0])) {
			return false;
		}
	}
	return true;
}

function toDigestAlgorithm(algorithm: string): DigestAlgorithm {
	const algo = algorithm.toUpperCase();
	if (algo !== 'SHA-256' && algo !== 'SHA-512') {
		throw new Error(`Unsupported digest algorithm '${algorithm}'.`);
	}
	return algo;
}

function hashBody(
	body: DigestBody,
	algo: DigestAlgorithm,
): Promise<ArrayBuffer> {
	const data = typeof body === 'string' ? new TextEncoder().encode(body) : body;
	return crypto.subtle.digest(algo, data);
}

function arrayBuffersEqual(a: ArrayBuffer, b: ArrayBuffer): boolean {
	if (a.byteLength !== b.byteLength) return false;
	const viewA = new Uint8Array(a);
	const viewB = new Uint8Array(b);
	return viewA.every((byte, i) => byte === viewB[i]);
}
