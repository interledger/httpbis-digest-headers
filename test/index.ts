import { expect } from 'chai';
import { createContentDigestHeader, DigestAlgorithm, verifyContentDigest} from '../src/index'

describe('digest', () => {
    describe('.createContentDigestHeader', () => {
        it('creates a single digest from an empty body (SHA256)', () => {
            const test = undefined
            const digest = createContentDigestHeader(test,['sha-256'])
            expect(digest).to.equal('sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:')
        });
        it('creates a single digest from an empty body (SHA512)', () => {
            const test = undefined
            const digest = createContentDigestHeader(test,['sha-512'])
            expect(digest).to.equal('sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:')
        });
        it('creates a single digest from a body (SHA256)', () => {
            const test = '{hello:"world"}'
            const digest = createContentDigestHeader(test,['sha-256'])
            expect(digest).to.equal('sha-256=:LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs=:')
        });
        it('creates a single digest from a body (SHA512)', () => {
            const test = '{hello:"world"}'
            const digest = createContentDigestHeader(test,['sha-512'])
            expect(digest).to.equal('sha-512=:YwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:')
        });
        it('creates multiple digests from empty body', () => {
            const test = undefined
            const digest = createContentDigestHeader(test,['sha-256', 'sha-512'])
            expect(digest).to.equal('sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:, sha-512=:z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg==:')
            return
        });
        it('creates multiple digests from a body', () => {
            const test = '{hello:"world"}'
            const digest = createContentDigestHeader(test,['sha-256', 'sha-512'])
            expect(digest).to.equal('sha-256=:LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs=:, sha-512=:YwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:')
            return
        });
        it('throws  with invalid digest algorithm', () => {
            expect(createContentDigestHeader.bind(undefined,'', ['nonsense' as DigestAlgorithm]))
                .to.throw(/^Unsupported digest algorithm/)
        });
    });
    
    describe('.verifyContentDigest', () => {
        it('verifies a single digest (SHA256)', () => {
            expect(verifyContentDigest('{hello:"world"}', 'sha-256=:LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs=:'))
                .to.be.true
        });
        it('verifies a single digest with empty body (SHA256)', () => {
            expect(verifyContentDigest(undefined, 'sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:'))
                .to.be.true
        });
        it('verifies a single digest (SHA512)', () => {
            expect(verifyContentDigest('{hello:"world"}', 'sha-512=:YwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:'))
                .to.be.true
        });
        it('doesn\'t verify a single invalid digest (SHA256)', () => {
            expect(verifyContentDigest('{goodbye:"world"}', 'sha-256=:LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs=:'))
                .to.be.false
        });
        it('doesn\'t verify a single invalid digest (SHA512)', () => {
            expect(verifyContentDigest('{goodbye:"world"}', 'sha-512=:YwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:'))
                .to.be.false
        });
        it('throws with invalid digest algorithm', () => {
            expect(verifyContentDigest.bind(undefined, '{hello:"world"}', 'md5=:YwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:'))
                .to.throw(/^Unsupported digest algorithm/)
        });
        it('throws with invalid header', () => {
            expect(verifyContentDigest.bind(undefined, '', 'sha-256="NOT A HASH"'))
                .to.throw(/^Invalid value for digest/)
            expect(verifyContentDigest.bind(undefined, '', 'sha-256=LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs='))
                .to.throw(/^Parse error/)
        });
        it('verifies two digests (SHA256 and SHA512)', () => {
            expect(verifyContentDigest('{hello:"world"}', 'sha-256=:LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs=:, sha-512=:YwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:'))
                .to.be.true
        });
        it('verifies two digests (SHA256 and SHA512) in any order', () => {
            expect(verifyContentDigest('{hello:"world"}', 'sha-512=:YwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:, sha-256=:LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs=:'))
                .to.be.true
        });
        it('doesn\'t verify if any digest fails', () => {
            expect(verifyContentDigest('{hello:"world"}', 'sha-512=:ZwRB5Y5G6jIfS1V0gBi59+hVKgu+vFjZKmeXdqMQQjwrwh5hA0vNbwDQi30SCiOK+e2dRs3P4tMo72WT3BfmQg==:, sha-256=:LsWDvMD3TQ5hD1FciIKL6ePw7YR8BVI5dD6NnJwusRs=:'))
                .to.be.false
        });
    });
})