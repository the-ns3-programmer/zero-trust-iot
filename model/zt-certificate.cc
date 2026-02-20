
#include "zt-certificate.h"
#include <cryptopp/osrng.h>
#include <cryptopp/pssr.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/files.h>
#include <sstream>
#include <ns3/core-module.h>

using namespace CryptoPP;

/**
 * \class CertificateAuthority
 * \brief Issues and signs certificates for Zero Trust identity validation.
 */
CertificateAuthority::CertificateAuthority() {
  AutoSeededRandomPool prng;
  privateKey.GenerateRandomWithKeySize(prng, 1024);
  publicKey = privateKey;
}

/**
 * \brief Signs a certificate with node ID, role, and expiry.
 * \param nodeId ID of the node requesting certificate
 * \param role Role assigned to the node (e.g., sensor, gateway)
 * \param expiry Expiry timestamp of the certificate
 * \return Signed certificate string with base64-encoded signature
 */
std::string CertificateAuthority::SignIdentity(uint32_t nodeId, const std::string& role, time_t expiry) {
  AutoSeededRandomPool prng;

  std::ostringstream cert;
  cert << "ID:" << nodeId << "|ROLE:" << role << "|EXP:" << expiry;

  RSASS<PSSR, SHA1>::Signer signer(privateKey);
  std::string signature;
  StringSource(cert.str(), true,
    new SignerFilter(prng, signer,
      new StringSink(signature)));

  std::string encodedSig;
  StringSource(signature, true,
    new Base64Encoder(new StringSink(encodedSig), false));

  return cert.str() + "|SIG:" + encodedSig;
}

/**
 * \brief Returns the public key of the Certificate Authority.
 * \return RSA public key
 */
RSA::PublicKey CertificateAuthority::GetPublicKey() const {
  return publicKey;
}

/**
 * \brief Sets the CA public key for the policy engine.
 * \param pub RSA public key of the certificate authority
 */
void ZtPolicyEngineWithCert::SetCaPublicKey(RSA::PublicKey pub) {
  caPublicKey = pub;
}

/**
 * \brief Revokes access for a specific node.
 * \param nodeId ID of the node to be revoked
 */
void ZtPolicyEngineWithCert::Revoke(uint32_t nodeId) {
  revoke.insert(nodeId);
}

/**
 * \brief Verifies and authorizes a node based on its certificate.
 * \param nodeId ID of the node attempting access
 * \param role Role of the node
 * \param certStr Certificate string to validate
 * \return True if the certificate is valid and authorization succeeds
 */
bool ZtPolicyEngineWithCert::Authorize(uint32_t nodeId, const std::string& role, const std::string& certStr) {
  using namespace ns3;

  if (revoke.find(nodeId) != revoke.end()) {
    NS_LOG_UNCOND("ZT-CERT: Node " << nodeId << " is revoked");
    return false;
  }

  std::string content, sig;
  size_t sigPos = certStr.find("|SIG:");
  if (sigPos == std::string::npos) return false;
  content = certStr.substr(0, sigPos);
  sig = certStr.substr(sigPos + 5);

  std::string decodedSig;
  StringSource(sig, true, new Base64Decoder(new StringSink(decodedSig)));

  RSASS<PSSR, SHA1>::Verifier verifier(caPublicKey);
  bool valid = false;
  StringSource(decodedSig + content, true,
    new SignatureVerificationFilter(verifier,
      new ArraySink((byte*)&valid, sizeof(valid)),
      SignatureVerificationFilter::PUT_RESULT | SignatureVerificationFilter::SIGNATURE_AT_BEGIN));

  if (!valid) {
    NS_LOG_UNCOND("ZT-CERT: Signature invalid");
    return false;
  }

  std::istringstream ss(content);
  std::string token;
  uint32_t idParsed = 0;
  std::string roleParsed;
  time_t expiry = 0;

  while (std::getline(ss, token, '|')) {
    if (token.find("ID:") == 0)
      idParsed = std::stoul(token.substr(3));
    else if (token.find("ROLE:") == 0)
      roleParsed = token.substr(5);
    else if (token.find("EXP:") == 0)
      expiry = std::stol(token.substr(4));
  }

  if (idParsed != nodeId || roleParsed != role) {
    NS_LOG_UNCOND("ZT-CERT: Identity mismatch");
    return false;
  }

  time_t now = std::time(nullptr);
  if (now > expiry) {
    NS_LOG_UNCOND("ZT-CERT: Certificate expired");
    return false;
  }

  return true;
}

