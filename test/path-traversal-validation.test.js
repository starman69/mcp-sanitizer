/**
 * File path / sensitive-file access validation regression tests.
 *
 * Asserts CORRECT (post-fix) behavior, so these are RED until the fix lands.
 * Source: GHSA-7w82-6f9j-v9jp (EQSTLab / SK Shieldus) — file path sanitizer
 * permits arbitrary user-home absolute paths (CWE-22).
 *
 * Fix direction: drop `/home/` and `/Users/` from the absolute-path allowlist
 * and add a sensitive-file/dotdir blocklist. A `blocked: true` result is the
 * boundary consumers rely on before reading/writing a path for `file_reader` /
 * `file_writer` tools.
 */

const MCPSanitizer = require('../src/index');

const sanitizer = new MCPSanitizer();

function isBlocked (path) {
  return sanitizer.sanitize(path, { type: 'file_path' }).blocked === true;
}

describe('Path traversal: sensitive file access (GHSA-7w82-6f9j-v9jp)', () => {
  describe('baseline — already blocked (regression guard)', () => {
    const alreadyBlocked = [
      '/etc/passwd',
      '/root/.ssh/id_rsa',
      '/proc/self/environ'
    ];

    it.each(alreadyBlocked)('blocks %s', (path) => {
      expect(isBlocked(path)).toBe(true);
    });
  });

  describe('reported bypasses — sensitive user-home files must be blocked', () => {
    const reportedBypasses = [
      '/home/victim/.ssh/id_rsa',
      '/home/victim/.aws/credentials',
      '/Users/victim/.ssh/id_rsa',
      '/home/victim/.gnupg/secring.gpg',
      '/home/victim/.kube/config',
      '/home/victim/.config/gcloud/credentials.db',
      '/home/victim/.npmrc',
      '/home/victim/.netrc',
      '/home/victim/.env'
    ];

    it.each(reportedBypasses)('blocks %s', (path) => {
      expect(isBlocked(path)).toBe(true);
    });
  });
});
