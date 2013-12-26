/* crypto/cms/cms_lcl.h */
/* Written by Dr Stephen N Henson (steve@openssl.org) for the OpenSSL
 * project.
 */
/* ====================================================================
 * Copyright (c) 2008 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */
/*
 * Include code written by Antonio Eletto (antele@gmail.com)
 * RFC 5544 (Syntax for Binding Documents with Time-Stamps)
 */

#ifndef HEADER_CMS_LCL_H
#define HEADER_CMS_LCL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* Cryptographic message syntax (CMS) structures: taken
 * from RFC3852
 */

/* Forward references */

typedef struct CMS_IssuerAndSerialNumber_st CMS_IssuerAndSerialNumber;
typedef struct CMS_EncapsulatedContentInfo_st CMS_EncapsulatedContentInfo;
typedef struct CMS_SignerIdentifier_st CMS_SignerIdentifier;
typedef struct CMS_SignedData_st CMS_SignedData;
typedef struct CMS_OtherRevocationInfoFormat_st CMS_OtherRevocationInfoFormat;
typedef struct CMS_OriginatorInfo_st CMS_OriginatorInfo;
typedef struct CMS_EncryptedContentInfo_st CMS_EncryptedContentInfo;
typedef struct CMS_EnvelopedData_st CMS_EnvelopedData;
typedef struct CMS_DigestedData_st CMS_DigestedData;
typedef struct CMS_EncryptedData_st CMS_EncryptedData;
typedef struct CMS_AuthenticatedData_st CMS_AuthenticatedData;
typedef struct CMS_CompressedData_st CMS_CompressedData;
typedef struct CMS_OtherCertificateFormat_st CMS_OtherCertificateFormat;
typedef struct CMS_KeyTransRecipientInfo_st CMS_KeyTransRecipientInfo;
typedef struct CMS_OriginatorPublicKey_st CMS_OriginatorPublicKey;
typedef struct CMS_OriginatorIdentifierOrKey_st CMS_OriginatorIdentifierOrKey;
typedef struct CMS_KeyAgreeRecipientInfo_st CMS_KeyAgreeRecipientInfo;
typedef struct CMS_OtherKeyAttribute_st CMS_OtherKeyAttribute;
typedef struct CMS_RecipientKeyIdentifier_st CMS_RecipientKeyIdentifier;
typedef struct CMS_KeyAgreeRecipientIdentifier_st CMS_KeyAgreeRecipientIdentifier;
typedef struct CMS_RecipientEncryptedKey_st CMS_RecipientEncryptedKey;
typedef struct CMS_KEKIdentifier_st CMS_KEKIdentifier;
typedef struct CMS_KEKRecipientInfo_st CMS_KEKRecipientInfo;
typedef struct CMS_PasswordRecipientInfo_st CMS_PasswordRecipientInfo;
typedef struct CMS_OtherRecipientInfo_st CMS_OtherRecipientInfo;
typedef struct CMS_ReceiptsFrom_st CMS_ReceiptsFrom;
/* TSD structures: from RFC 5544 */
typedef struct CMS_TimestampedData_st CMS_TimestampedData;
typedef struct CMS_MetaData_st CMS_MetaData;
typedef struct CMS_Evidence_st CMS_Evidence;
typedef struct CMS_TimeStampTokenEvidence_st CMS_TimeStampTokenEvidence;
typedef struct CMS_TimeStampAndCRL_st CMS_TimeStampAndCRL;
typedef struct CMS_EvidenceRecord_st CMS_EvidenceRecord;
typedef struct CMS_EncryptionInfo_st CMS_EncryptionInfo;
typedef struct CMS_ArchiveTimeStamp_st CMS_ArchiveTimeStamp;
typedef struct CMS_ArchiveTimeStampChain_st CMS_ArchiveTimeStampChain;
typedef struct CMS_OtherEvidence_st CMS_OtherEvidence;
typedef struct CMS_TimeStampResp_st CMS_TimeStampResp;
typedef struct CMS_PKIStatusInfo_st CMS_PKIStatusInfo;
typedef struct CMS_TSTInfo_st CMS_TSTInfo;
typedef struct CMS_MessageImprint_st CMS_MessageImprint;
typedef struct CMS_Accuracy_st CMS_Accuracy;

struct CMS_ContentInfo_st
	{
	ASN1_OBJECT *contentType;
	union	{
		ASN1_OCTET_STRING *data;
		CMS_SignedData *signedData;
		CMS_EnvelopedData *envelopedData;
		CMS_DigestedData *digestedData;
		CMS_EncryptedData *encryptedData;
		CMS_AuthenticatedData *authenticatedData;
		CMS_CompressedData *compressedData;
		CMS_TimestampedData *timestampedData;
		ASN1_TYPE *other;
		/* Other types ... */
		void *otherData;
		} d;
	};

struct CMS_SignedData_st
	{
	long version;
	STACK_OF(X509_ALGOR) *digestAlgorithms;
	CMS_EncapsulatedContentInfo *encapContentInfo;
	STACK_OF(CMS_CertificateChoices) *certificates;
	STACK_OF(CMS_RevocationInfoChoice) *crls;
	STACK_OF(CMS_SignerInfo) *signerInfos;
	};
 
struct CMS_EncapsulatedContentInfo_st
	{
	ASN1_OBJECT *eContentType;
	ASN1_OCTET_STRING *eContent;
	/* Set to 1 if incomplete structure only part set up */
	int partial;
	};

struct CMS_SignerInfo_st
	{
	long version;
	CMS_SignerIdentifier *sid;
	X509_ALGOR *digestAlgorithm;
	STACK_OF(X509_ATTRIBUTE) *signedAttrs;
	X509_ALGOR *signatureAlgorithm;
	ASN1_OCTET_STRING *signature;
	STACK_OF(X509_ATTRIBUTE) *unsignedAttrs;
	/* Signing certificate and key */
	X509 *signer;
	EVP_PKEY *pkey;
	};

struct CMS_SignerIdentifier_st
	{
	int type;
	union	{
		CMS_IssuerAndSerialNumber *issuerAndSerialNumber;
		ASN1_OCTET_STRING *subjectKeyIdentifier;
		} d;
	};

struct CMS_EnvelopedData_st
	{
	long version;
	CMS_OriginatorInfo *originatorInfo;
	STACK_OF(CMS_RecipientInfo) *recipientInfos;
	CMS_EncryptedContentInfo *encryptedContentInfo;
	STACK_OF(X509_ATTRIBUTE) *unprotectedAttrs;
	};

struct CMS_OriginatorInfo_st
	{
	STACK_OF(CMS_CertificateChoices) *certificates;
	STACK_OF(CMS_RevocationInfoChoice) *crls;
	};

struct CMS_EncryptedContentInfo_st
	{
	ASN1_OBJECT *contentType;
	X509_ALGOR *contentEncryptionAlgorithm;
	ASN1_OCTET_STRING *encryptedContent;
	/* Content encryption algorithm and key */
	const EVP_CIPHER *cipher;
	unsigned char *key;
	size_t keylen;
	/* Set to 1 if we are debugging decrypt and don't fake keys for MMA */
	int debug;
	};

struct CMS_RecipientInfo_st
	{
 	int type;
 	union	{
  	 	CMS_KeyTransRecipientInfo *ktri;
   		CMS_KeyAgreeRecipientInfo *kari;
   		CMS_KEKRecipientInfo *kekri;
		CMS_PasswordRecipientInfo *pwri;
		CMS_OtherRecipientInfo *ori;
		} d;
	};

typedef CMS_SignerIdentifier CMS_RecipientIdentifier;

struct CMS_KeyTransRecipientInfo_st
	{
	long version;
	CMS_RecipientIdentifier *rid;
	X509_ALGOR *keyEncryptionAlgorithm;
	ASN1_OCTET_STRING *encryptedKey;
	/* Recipient Key and cert */
	X509 *recip;
	EVP_PKEY *pkey;
	};

struct CMS_KeyAgreeRecipientInfo_st
	{
	long version;
	CMS_OriginatorIdentifierOrKey *originator;
	ASN1_OCTET_STRING *ukm;
 	X509_ALGOR *keyEncryptionAlgorithm;
	STACK_OF(CMS_RecipientEncryptedKey) *recipientEncryptedKeys;
	};

struct CMS_OriginatorIdentifierOrKey_st
	{
	int type;
	union	{
		CMS_IssuerAndSerialNumber *issuerAndSerialNumber;
		ASN1_OCTET_STRING *subjectKeyIdentifier;
		CMS_OriginatorPublicKey *originatorKey;
		} d;
	};

struct CMS_OriginatorPublicKey_st
	{
	X509_ALGOR *algorithm;
	ASN1_BIT_STRING *publicKey;
	};

struct CMS_RecipientEncryptedKey_st
	{
 	CMS_KeyAgreeRecipientIdentifier *rid;
 	ASN1_OCTET_STRING *encryptedKey;
	};

struct CMS_KeyAgreeRecipientIdentifier_st
	{
	int type;
	union	{
		CMS_IssuerAndSerialNumber *issuerAndSerialNumber;
		CMS_RecipientKeyIdentifier *rKeyId;
		} d;
	};

struct CMS_RecipientKeyIdentifier_st
	{
 	ASN1_OCTET_STRING *subjectKeyIdentifier;
 	ASN1_GENERALIZEDTIME *date;
 	CMS_OtherKeyAttribute *other;
	};

struct CMS_KEKRecipientInfo_st
	{
 	long version;
 	CMS_KEKIdentifier *kekid;
 	X509_ALGOR *keyEncryptionAlgorithm;
 	ASN1_OCTET_STRING *encryptedKey;
	/* Extra info: symmetric key to use */
	unsigned char *key;
	size_t keylen;
	};

struct CMS_KEKIdentifier_st
	{
 	ASN1_OCTET_STRING *keyIdentifier;
 	ASN1_GENERALIZEDTIME *date;
 	CMS_OtherKeyAttribute *other;
	};

struct CMS_PasswordRecipientInfo_st
	{
 	long version;
 	X509_ALGOR *keyDerivationAlgorithm;
 	X509_ALGOR *keyEncryptionAlgorithm;
 	ASN1_OCTET_STRING *encryptedKey;
	/* Extra info: password to use */
	unsigned char *pass;
	size_t passlen;
	};

struct CMS_OtherRecipientInfo_st
	{
 	ASN1_OBJECT *oriType;
 	ASN1_TYPE *oriValue;
	};

struct CMS_DigestedData_st
	{
	long version;
	X509_ALGOR *digestAlgorithm;
	CMS_EncapsulatedContentInfo *encapContentInfo;
	ASN1_OCTET_STRING *digest;
	};

struct CMS_EncryptedData_st
	{
	long version;
	CMS_EncryptedContentInfo *encryptedContentInfo;
	STACK_OF(X509_ATTRIBUTE) *unprotectedAttrs;
	};

struct CMS_AuthenticatedData_st
	{
	long version;
	CMS_OriginatorInfo *originatorInfo;
	STACK_OF(CMS_RecipientInfo) *recipientInfos;
	X509_ALGOR *macAlgorithm;
	X509_ALGOR *digestAlgorithm;
	CMS_EncapsulatedContentInfo *encapContentInfo;
	STACK_OF(X509_ATTRIBUTE) *authAttrs;
	ASN1_OCTET_STRING *mac;
	STACK_OF(X509_ATTRIBUTE) *unauthAttrs;
	};

struct CMS_CompressedData_st
	{
	long version;
	X509_ALGOR *compressionAlgorithm;
	STACK_OF(CMS_RecipientInfo) *recipientInfos;
	CMS_EncapsulatedContentInfo *encapContentInfo;
	};

struct CMS_RevocationInfoChoice_st
	{
	int type;
	union	{
		X509_CRL *crl;
		CMS_OtherRevocationInfoFormat *other;
		} d;
	};

#define CMS_REVCHOICE_CRL		0
#define CMS_REVCHOICE_OTHER		1

struct CMS_OtherRevocationInfoFormat_st
	{
	ASN1_OBJECT *otherRevInfoFormat;
 	ASN1_TYPE *otherRevInfo;
	};

struct CMS_CertificateChoices
	{
	int type;
	union
		{
		X509 *certificate;
		ASN1_STRING *extendedCertificate;	/* Obsolete */
		ASN1_STRING *v1AttrCert;	/* Left encoded for now */
		ASN1_STRING *v2AttrCert;	/* Left encoded for now */
		CMS_OtherCertificateFormat *other;
		} d;
	};

#define CMS_CERTCHOICE_CERT			0
#define CMS_CERTCHOICE_EXCERT		1
#define CMS_CERTCHOICE_V1ACERT		2
#define CMS_CERTCHOICE_V2ACERT		3
#define CMS_CERTCHOICE_OTHER		4

struct CMS_OtherCertificateFormat_st
	{
	ASN1_OBJECT *otherCertFormat;
 	ASN1_TYPE *otherCert;
	};

/* This is also defined in pkcs7.h but we duplicate it
 * to allow the CMS code to be independent of PKCS#7
 */

struct CMS_IssuerAndSerialNumber_st
	{
	X509_NAME *issuer;
	ASN1_INTEGER *serialNumber;
	};

struct CMS_OtherKeyAttribute_st
	{
	ASN1_OBJECT *keyAttrId;
 	ASN1_TYPE *keyAttr;
	};

/* ESS structures */

#ifdef HEADER_X509V3_H

struct CMS_ReceiptRequest_st
	{
	ASN1_OCTET_STRING *signedContentIdentifier;
	CMS_ReceiptsFrom *receiptsFrom;
	STACK_OF(GENERAL_NAMES) *receiptsTo;
	};


struct CMS_ReceiptsFrom_st
	{
	int type;
	union
		{
		long allOrFirstTier;
		STACK_OF(GENERAL_NAMES) *receiptList;
		} d;
	};
#endif

struct CMS_Receipt_st
	{
	long version;
	ASN1_OBJECT *contentType;
	ASN1_OCTET_STRING *signedContentIdentifier;
	ASN1_OCTET_STRING *originatorSignatureValue;
	};


/* Time Stamped Data (TSD) structures:
 * taken from RFC 5544
 *
 * TimeStampedData ::= SEQUENCE {
 *       version              INTEGER { v1(1) },
 *       dataUri              IA5String OPTIONAL,
 *       metaData             MetaData OPTIONAL,
 *       content              OCTET STRING OPTIONAL,
 *       temporalEvidence     Evidence }
 */
struct CMS_TimestampedData_st
	{
	ASN1_INTEGER *version;
	ASN1_IA5STRING *dataUri;
	CMS_MetaData *metaData;
	ASN1_OCTET_STRING *content;
	CMS_Evidence *temporalEvidence;
	};

/* MetaData ::= SEQUENCE {
 *       hashProtected        BOOLEAN,
 *       fileName             UTF8String OPTIONAL,
 *       mediaType            IA5String OPTIONAL,
 *       otherMetaData        Attributes2 OPTIONAL }
 *
 * Attributes2 ::=
 * 		SET SIZE(1..MAX) OF Attribute -- according to RFC 5652
 */
struct CMS_MetaData_st
	{
	ASN1_BOOLEAN *hashProtected;
	ASN1_UTF8STRING *fileName;
	ASN1_IA5STRING *mediaType;
	STACK_OF(X509_ATTRIBUTE) *otherMetaData;
	};

/* Evidence ::= CHOICE {
 *		tstEvidence    [0] TimeStampTokenEvidence,   -- see RFC 3161
 *		ersEvidence    [1] EvidenceRecord,           -- see RFC 4998
 *	  	otherEvidence  [2] OtherEvidence }
 *
 * TimeStampTokenEvidence ::=
 *       SEQUENCE SIZE(1..MAX) OF TimeStampAndCRL
 */
DECLARE_STACK_OF(CMS_TimeStampAndCRL)
struct CMS_Evidence_st
	{
	int type;
	union
		{
		STACK_OF(CMS_TimeStampAndCRL) *tstEvidence;  	// -- see RFC 3161
		CMS_EvidenceRecord *ersEvidence;  				// -- see RFC 4998
		CMS_OtherEvidence *otherEvidence;
		} d;
	};

#define CMS_EVIDENCE_TIMESTAMP 	0
#define CMS_EVIDENCE_RECORD		1
#define CMS_EVIDENCE_OTHER 		2

/* TimeStampAndCRL ::= SEQUENCE {
 *		timeStamp TimeStampToken,          	-- according to RFC 3161
 *	    crl       CertificateList OPTIONAL 	-- according to RFC 5280 }
 */

typedef CMS_ContentInfo	 CMS_TimeStampToken;

struct CMS_TimeStampAndCRL_st
	{
	CMS_TimeStampToken *timeStamp;  	// -- according to RFC 3161
	X509_CRL *crl;  					// -- according to RFC 5280
	};

/* Time Stamp Token Info structure:
 * taken from RFC 3161
 *
 * This is also defined in ts.h but we duplicate it
 * to allow the CMS code to be independent from PKCS#7
 *
 * TimeStampResp ::= SEQUENCE  {
 *      status                  PKIStatusInfo,
 *      timeStampToken          TimeStampToken     OPTIONAL  }
 */
struct CMS_TimeStampResp_st
	{
	CMS_PKIStatusInfo *status;
	CMS_TimeStampToken *timeStampToken;
	};

/* This is also defined in ts.h but we duplicate it
 * to allow the CMS code to be independent from PKCS#7
 *
 * PKIStatusInfo ::= SEQUENCE {
 *     status        PKIStatus,
 *     statusString  PKIFreeText     OPTIONAL,
 *     failInfo      PKIFailureInfo  OPTIONAL  }
 */
struct CMS_PKIStatusInfo_st
	{
	ASN1_INTEGER *status;
	STACK_OF(ASN1_UTF8STRING) *statusString;
	ASN1_BIT_STRING *failInfo;
	};

/* This is also defined in ts.h but we duplicate it
 * to allow the CMS code to be independent from PKCS#7
 *
 *
 * TSTInfo ::= SEQUENCE  {
 *  	version                      INTEGER  { v1(1) },
 *  	policy                       TSAPolicyId,
 *  	messageImprint               MessageImprint,
 *    	  -- MUST have the same value as the similar field in
 *    	  -- TimeStampReq
 *  	serialNumber                 INTEGER,
 *   	  -- Time-Stamping users MUST be ready to accommodate integers
 *   	  -- up to 160 bits.
 *  	genTime                      GeneralizedTime,
 *  	accuracy                     Accuracy                 OPTIONAL,
 *  	ordering                     BOOLEAN             DEFAULT FALSE,
 *  	nonce                        INTEGER                  OPTIONAL,
 *    	  -- MUST be present if the similar field was present
 *    	  -- in TimeStampReq.  In that case it MUST have the same value.
 *  	tsa                          [0] GeneralName          OPTIONAL,
 *  	extensions                   [1] IMPLICIT Extensions  OPTIONAL   }
 */
struct CMS_TSTInfo_st
	{
	ASN1_INTEGER *version;
	ASN1_OBJECT *policy;
	CMS_MessageImprint *messageImprint;
	ASN1_INTEGER *serialNumber;
	ASN1_GENERALIZEDTIME *genTime;
	CMS_Accuracy *accuracy;
	ASN1_BOOLEAN ordering;
	ASN1_INTEGER *nonce;
	GENERAL_NAME *tsa;
	STACK_OF(X509_EXTENSION) *extensions;
	};

/* MessageImprint ::= SEQUENCE  {
 *	   hashAlgorithm                AlgorithmIdentifier,
 *	   hashedMessage                OCTET STRING  }
 */
struct CMS_MessageImprint_st
	{
	X509_ALGOR *hashAlgorithm;
	ASN1_OCTET_STRING *hashedMessage;
	};

/*
 * Accuracy ::= SEQUENCE {
 * 	   seconds        INTEGER           OPTIONAL,
 *     millis     [0] INTEGER  (1..999) OPTIONAL,
 *     micros     [1] INTEGER  (1..999) OPTIONAL  }
 */

struct CMS_Accuracy_st
	{
	ASN1_INTEGER *seconds;
	ASN1_INTEGER *millis;
	ASN1_INTEGER *micros;
	};

/* OtherEvidence ::= SEQUENCE {
 *      oeType  OBJECT IDENTIFIER,
 *      oeValue ANY DEFINED BY oeType }
 */
struct CMS_OtherEvidence_st
	{
	ASN1_OBJECT *oeType;
    ASN1_TYPE *oeValue;
	};

/* Evidence Record Syntax (ERS) structure:
 * taken from RFC 4998
 *
 * EvidenceRecord ::= SEQUENCE {
 *     version                   INTEGER { v1(1) } ,
 *     digestAlgorithms          SEQUENCE OF AlgorithmIdentifier,
 *     cryptoInfos               [0] CryptoInfos OPTIONAL,
 *     encryptionInfo            [1] EncryptionInfo OPTIONAL,
 *     archiveTimeStampSequence  ArchiveTimeStampSequence }
 *
 * CryptoInfos ::= SEQUENCE SIZE (1..MAX) OF Attribute
 *
 * ArchiveTimeStampSequence ::= SEQUENCE OF ArchiveTimeStampChain
 */
//DECLARE_STACK_OF(CMS_ArchiveTimeStampChain)

struct CMS_EvidenceRecord_st
	{
	ASN1_INTEGER *version;
	STACK_OF(X509_ALGOR) *digestAlgorithms;
	STACK_OF(X509_ATTRIBUTE) *cryptoInfos;
	CMS_EncryptionInfo *encryptionInfo;
	STACK_OF(CMS_ArchiveTimeStampChain) *archiveTimeStampSequence;
	};

/* EncryptionInfo ::= SEQUENCE {
 *     encryptionInfoType     OBJECT IDENTIFIER,
 *     encryptionInfoValue    ANY DEFINED BY encryptionInfoType }
 */
struct CMS_EncryptionInfo_st
	{
	ASN1_OBJECT *encryptionInfoType;
	ASN1_TYPE *encryptionInfoValue;
	};

/* ArchiveTimeStamp ::= SEQUENCE {
 *    digestAlgorithm [0] AlgorithmIdentifier OPTIONAL,
 *    attributes      [1] Attributes OPTIONAL,
 *    reducedHashtree [2] SEQUENCE OF PartialHashtree OPTIONAL,
 *    timeStamp       ContentInfo}
 *
 * PartialHashtree ::= SEQUENCE OF OCTET STRING
 *
 * Attributes ::= SET SIZE (1..MAX) OF Attribute
 */
struct CMS_ArchiveTimeStamp_st
	{
	X509_ALGOR *digestAlgorithm;
	STACK_OF(X509_ATTRIBUTE) *attributes;
	STACK_OF(ASN1_OCTET_STRING) *reducedHashtree;
	CMS_ContentInfo *timeStamp;
	};

/* ArchiveTimeStampChain ::= SEQUENCE OF ArchiveTimeStamp
 */
//DECLARE_STACK_OF(CMS_ArchiveTimeStamp)

struct CMS_ArchiveTimeStampChain_st
	{
	STACK_OF(CMS_ArchiveTimeStamp) *archiveTimeStamp;
	};


DECLARE_ASN1_FUNCTIONS(CMS_ContentInfo)
DECLARE_ASN1_ITEM(CMS_SignerInfo)
DECLARE_ASN1_ITEM(CMS_IssuerAndSerialNumber)
DECLARE_ASN1_ITEM(CMS_Attributes_Sign)
DECLARE_ASN1_ITEM(CMS_Attributes_Verify)
DECLARE_ASN1_ITEM(CMS_RecipientInfo)
DECLARE_ASN1_ITEM(CMS_PasswordRecipientInfo)
DECLARE_ASN1_ITEM(CMS_TimeStampAndCRL)
DECLARE_ASN1_ITEM(CMS_TSTInfo)
DECLARE_ASN1_ALLOC_FUNCTIONS(CMS_IssuerAndSerialNumber)
DECLARE_ASN1_FUNCTIONS(CMS_TimestampedData)
DECLARE_ASN1_FUNCTIONS(CMS_TSTInfo)
DECLARE_ASN1_FUNCTIONS(CMS_MetaData)

#define CMS_SIGNERINFO_ISSUER_SERIAL	0
#define CMS_SIGNERINFO_KEYIDENTIFIER	1

#define CMS_RECIPINFO_ISSUER_SERIAL	0
#define CMS_RECIPINFO_KEYIDENTIFIER	1

BIO *cms_content_bio(CMS_ContentInfo *cms);

CMS_ContentInfo *cms_Data_create(void);

CMS_ContentInfo *cms_DigestedData_create(const EVP_MD *md);
BIO *cms_DigestedData_init_bio(CMS_ContentInfo *cms);
int cms_DigestedData_do_final(CMS_ContentInfo *cms, BIO *chain, int verify);

BIO *cms_SignedData_init_bio(CMS_ContentInfo *cms);
int cms_SignedData_final(CMS_ContentInfo *cms, BIO *chain);
int cms_set1_SignerIdentifier(CMS_SignerIdentifier *sid, X509 *cert, int type);
int cms_SignerIdentifier_get0_signer_id(CMS_SignerIdentifier *sid,
					ASN1_OCTET_STRING **keyid,
					X509_NAME **issuer, ASN1_INTEGER **sno);
int cms_SignerIdentifier_cert_cmp(CMS_SignerIdentifier *sid, X509 *cert);

CMS_ContentInfo *cms_CompressedData_create(int comp_nid);
BIO *cms_CompressedData_init_bio(CMS_ContentInfo *cms);

void cms_DigestAlgorithm_set(X509_ALGOR *alg, const EVP_MD *md);
BIO *cms_DigestAlgorithm_init_bio(X509_ALGOR *digestAlgorithm);
int cms_DigestAlgorithm_find_ctx(EVP_MD_CTX *mctx, BIO *chain,
					X509_ALGOR *mdalg);

BIO *cms_EncryptedContent_init_bio(CMS_EncryptedContentInfo *ec);
BIO *cms_EncryptedData_init_bio(CMS_ContentInfo *cms);
int cms_EncryptedContent_init(CMS_EncryptedContentInfo *ec, 
				const EVP_CIPHER *cipher,
				const unsigned char *key, size_t keylen);

int cms_Receipt_verify(CMS_ContentInfo *cms, CMS_ContentInfo *req_cms);
int cms_msgSigDigest_add1(CMS_SignerInfo *dest, CMS_SignerInfo *src);
ASN1_OCTET_STRING *cms_encode_Receipt(CMS_SignerInfo *si);

BIO *cms_EnvelopedData_init_bio(CMS_ContentInfo *cms);
CMS_EnvelopedData *cms_get0_enveloped(CMS_ContentInfo *cms);

/* PWRI routines */
int cms_RecipientInfo_pwri_crypt(CMS_ContentInfo *cms, CMS_RecipientInfo *ri,
							int en_de);

STACK_OF(CMS_TimeStampAndCRL) *cms_get0_timeStampTokenChain(CMS_ContentInfo *cms);
CMS_ContentInfo *cms_get_token(STACK_OF(CMS_TimeStampAndCRL) *tstEvidenceSequence, int index);
CMS_TSTInfo *cms_tstInfo_decode(CMS_ContentInfo *token);
int cms_metaData_encode(CMS_ContentInfo *cms, unsigned char **out);
//int cms_compute_content_digest(CMS_ContentInfo *cms, EVP_MD_CTX *mdContext, unsigned char *digest);
//int cms_compute_token_digest(CMS_ContentInfo *token, EVP_MD_CTX *mdContext, unsigned char *digest);
int cms_Token_signature_verify(CMS_ContentInfo *token, STACK_OF(X509) *certs,
		 X509_STORE *store, unsigned int flags);
int cms_Token_digest_verify(CMS_ContentInfo *cms, CMS_ContentInfo *token, int extToken);
int cms_check_dataUri(CMS_ContentInfo *cms);
CMS_MetaData *cms_get0_metaData(CMS_ContentInfo *cms);
CMS_MetaData *cms_new_metaData(char *fileName, char* mediaType, int flags);
int cms_digest_matching_verify(CMS_TSTInfo *tstInfo, unsigned char *digest, unsigned digestLength);


#ifdef  __cplusplus
}
#endif
#endif
