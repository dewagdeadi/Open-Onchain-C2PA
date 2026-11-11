Sample files from the C2PA Rust SDK test fixtures (https://github.com/contentauth/c2pa-rs,
sdk/tests/fixtures; MIT or Apache-2.0). They are signed with public test certificates
("C2PA Test Signing Cert", FOR TESTING ONLY). `es256-key.pem` is the matching public test key
(certs/es256.pem) for `cloud_manifest.c2pa`.

`video1.mp4`, `dashinit.mp4` and `cloud.jpg` (a remote manifest) are signed samples. The unsigned
`sample1.*` / `sample3.svg` files and a 200 KB cut of `sample1.mp3` are carriers: the tests embed real
Content Credentials into them using each format's C2PA layout, to exercise every container parser.
