## Report:

  

**Problem Statement:-**

  

A sample scenario where the tests fire some RPC calls to the two RPC servers ValidationServer and CommitServer. The ValidationServer is responsible for validating the incoming requests. CommitServer simulates the commit of the message.

  

The task is to ensure that the CommitServer implemented in commit/server/server.go reject any incoming messages that are directly sent to it without validation.

  

In other words, the commitServer should only respond with CommitResponse_SUCCESS (see protos/master/master.pb.go) if the message received was successfully validated by the validation server.

So a message must be first sent to a validation server, and then to the commit server. Otherwise it must be rejected by the CommitServer.

  

Things that are not allowed:

1. CommitServer and ValidationServer are not allowed to communicate in any way directly.

2. You are not allowed to modify test/ and protos/ directory.

**Solution Approach:**

The situation can be handled by taking into account the Public-Key Infrastructure.

As the message needs to be validated first before being requested to be committed. So the commit server should somehow needs to know or verify that if a message is directly coming to it without validation or after proper validation.

So to handle the situation, the validation server can sign the message with its private key, which it receives for validation and then the original message can be appended to signature with whitespace between them so that later commit server can separate the original plaintext message and the signature. (The message is appended as we can’t modify protos but need to transfer the signature as well as plain text)

After wards, when commit server will receive the request after validation of message, then the message itself has the signature and the original message and commit server can verify if the message is actually coming from the validation server. If the verification fails, like in the case of the non-validated message, then the Return Value is FAILURE.
