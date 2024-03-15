# Silent Payments

A rust implementation of BIP352: Silent Payments.

## About

**Warning: both this crate and BIP352 are still quite new.
Review this library carefully before using it with mainnet funds.**

This library supports creating and sending to silent payment addresses,
building on [`secp256k1`](https://docs.rs/secp256k1/latest/secp256k1)
`PublicKey` and `SecretKey` structs for the interface.
In the future, the library will probably be expanded to rely on structs from rust-bitcoin as well.

The library is split up in two parts: sending and receiving.

## Sending

For sending to a silent payment address, you can call the `sender::generate_recipient_pubkeys` function.
This function takes a list of silent payment recipients, as well as a `partial_secret`.

The `partial_secret` represents the sum of all input private keys multiplied with the input hash.
To compute the `partial_secret`, the `utils::sending::compute_partial_secret` function can be used,
although this requires exposing secret data to this library.
Other methods for calculating the `partial_secret` will be added later.

## Recipient

For receiving silent payments, we use the `receiving::Receiver` struct.
This `Receiver` struct implements a `scan_transaction` function that can be used to scan an incoming transaction for newly received payments.

The library also supports labels. One label, the change label, is included by default. You can optionally add additional labels before scanning by using the `add_label` function.

## Examples

We will soon add an `examples` folder that contains some simple sending and receiving examples.
In the meantime, you can look at `tests/vector_tests.rs` to see how sending and receiving works in more detail.

We are also working on a [wallet](https://github.com/cygnet3/sp-backend) that implements sending and receiving.
This might also be a useful resource to get a more accurate idea on how the library can be integrated with wallets.

## Tests

The `tests/resources` folder contains a copy of the test vectors as of February 7th 2024.

You can test the code using the test vectors by running `cargo test`.
