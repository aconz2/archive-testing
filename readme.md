```
ls src/*.rs | entr -c bash -c 'cargo build && git ls-files | cargo run create_v0 /tmp/archive.v0'
ls src/*.rs | entr -c bash -c 'cargo build && (cd ../linux; git ls-files | ../archive-testing/target/debug/archive-testing create_v0 /tmp/archive.v0)'
```
