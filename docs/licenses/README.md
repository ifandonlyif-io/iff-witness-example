# Browser dependency notices

The generated Witness browser bundle includes portions of ethers and the
Noble cryptography libraries. Their MIT license notices are retained here:

- [ethers](ethers-MIT.txt)
- [@noble/curves](noble-curves-MIT.txt)
- [@noble/hashes](noble-hashes-MIT.txt)

Exact installed dependency versions are pinned in
`../../package-lock.json`. Generated files also preserve legal
comments emitted by the bundler. Keep these notices with distributed browser
assets and update them if the bundled dependency set changes.

Other Go and development-tool dependencies are resolved from the module and
package lockfiles, not vendored into this source snapshot.

The separate Apostille example includes the MIT-licensed Core 0.1 and strict-JSON modules from `iff-apostille v0.1.0-alpha.1`. See the [full license](../../client/third-party/apostille/LICENSE) and [pinned source manifest](../../client/third-party/apostille/SOURCE.json). The generated `web/apostille-demo.js` carries the full notice.
