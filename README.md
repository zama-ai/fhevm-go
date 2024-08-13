<p align="center">
<!-- product name logo -->
  <img width=600 src="https://github.com/zama-ai/fhevm/assets/1384478/265d051c-e177-42b4-b9a2-d2b2e474131b">
</p>
<hr/>
<p align="center">
  <a href="https://docs.zama.ai/fhevm-go"> 📒 Read documentation</a> | <a href="https://zama.ai/community"> 💛 Community support</a>
</p>
<p align="center">
<!-- Version badge using shields.io -->
  <a href="https://github.com/zama-ai/fhevm-go/releases">
    <img src="https://img.shields.io/github/v/release/zama-ai/fhevm-go?style=flat-square">
  </a>
<!-- Zama Bounty Program -->
  <a href="https://github.com/zama-ai/bounty-program">
    <img src="https://img.shields.io/badge/Contribute-Zama%20Bounty%20Program-yellow?style=flat-square">
  </a>
</p>
<hr/>

**fhEVM-go** is an open-source library used to easily integrate the [fhEVM](https://docs.zama.ai/fhevm) into an EVM-compatible blockchain.

## Main features

fhEVM-go gives your EVM the ability to compute on encrypted data using fully homomorphic encryption by:

- a collection of operations on encrypted data via precompiled contracts
- various additional EVM components that support encrypted computation

## Getting started

In order to use the library, you need to clone the repository and build it. This is required because the library depends on the `tfhe-rs` library that needs to be built from source (for now), and Go doesn't support such a build.

```bash
git clone --recurse-submodules https://github.com/zama-ai/fhevm-go
cd fhevm-go
make build
```

That's it! You can now use it in your project by adding it to `go.mod`, and adding a `replace` to point to your local build. An example using `fhevm-go` v1.0.0:

```
...
require(
    ...
    github.com/zama-ai/fhevm-go v1.0.0
    ...
)

replace(
    ...
    github.com/zama-ai/fhevm-go v1.0.0 => /path/to/your/local/fhevm-go
    ...
)
...
```

> [!NOTE]
> The replace in necessary for now as Go build system can't build the `tfhe-rs` library that `fhevm-go` needs. It's therefore necessary that we build it manually as mentioned above, then point to our ready-to-use directory in `go.mod`.

## Regenerate protobuff files

To re-generate these files, install `protoc`, `protoc-gen-go` and `protoc-gen-go-grpc` and run protoc
`cd proto && protoc --go_out=../fhevm/kms --go_opt=paths=source_relative --go-grpc_out=../fhevm/kms --go-grpc_opt=paths=source_relative kms.proto && cd ..`.

## Documentation

Full, comprehensive documentation is available at [https://docs.zama.ai/fhevm-go](https://docs.zama.ai/fhevm-go).

## Target users

The library helps EVM maintainers to extend their EVM with the power of FHE. If you are looking for a library to deploy and use smart contracts on an fhEVM, you should better look at [https://github.com/zama-ai/fhevm](https://github.com/zama-ai/fhevm).

## Tutorials

- [Integration guide](https://docs.zama.ai/fhevm-go/getting-started/integration)

## Need support?

<a target="_blank" href="https://community.zama.ai">
  <img src="https://user-images.githubusercontent.com/5758427/231145251-9cb3f03f-3e0e-4750-afb8-2e6cf391fa43.png">
</a>

## License


This software is distributed under the BSD-3-Clause-Clear license. If you have any questions, please contact us at hello@zama.ai.
