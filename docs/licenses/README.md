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
