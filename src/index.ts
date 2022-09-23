import { createHash } from 'crypto'
import { ByteSequence, isByteSequence, isInnerList, Item, parseDictionary, serializeDictionary } from 'structured-headers'

export type DigestAlgorithm = 'sha-256' | 'sha-512'

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
    switch(algorithm) {
        case 'sha-256': return 'sha256'
        case 'sha-512': return 'sha512'
        default: throw new Error(`Unsupported digest algorithm ${algorithm}.`)
    }
}

/**
 * Create the content-digest header for a given message body
 * 
 * @param body the message body
 * @param algorithms the digest algorithms to use (only 'sha-256' and 'sha-512' supported)
 * @returns the string that can be used as the content-digest header value
 */
export function createContentDigestHeader(body: string | Buffer | undefined, algorithms: DigestAlgorithm[]): string {
    return serializeDictionary(new Map<string, Item>(algorithms.map(algo => {
        return ([ 
            algo, 
            [ 
                new ByteSequence(createHash(nodeAlgo(algo)).update(body || '').digest('base64')), 
                new Map(),
            ]]) as (readonly [string, Item])
    })))
}

/**
 * Verify a content-digest header against a message body
 * 
 * @param body the message body
 * @param digestHeader the content-digest header
 * @returns true if all digests in the header are verified, false if not
 */
export function verifyContentDigest(body: string | Buffer | undefined, digestHeader: string) {

    const digests = parseDictionary(digestHeader)
    for(const [algo, digest] of digests) {
        if(isInnerList(digest) || !isByteSequence(digest[0])) {
            throw new Error(`Invalid value for digest with algorithm key of '${algo}'`)
        }
        const hash = createHash(nodeAlgo(algo)).update(body || '').digest('base64')
        if(digest[0].toBase64() !== hash){
            return false
        }
    }
}
