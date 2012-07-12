/* crypto/cms/cms_tsd.c */
/* Written by Antonio Eletto (antele@gmail.com) for the OpenSSL
 * project 2012.
 *
 * RFC 5544
 */
/* ====================================================================
 * Copyright (c) 2012 The OpenSSL Project.  All rights reserved.
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

#include "cryptlib.h"
#include <openssl/asn1t.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/comp.h>
#include "cms_lcl.h"


//DECLARE_ASN1_ITEM(CMS_TimeStampAndCRL)
//DECLARE_STACK_OF(CMS_TimeStampAndCRL)


static CMS_TimestampedData *cms_get0_timestamped(CMS_ContentInfo *cms)
	{
	if (OBJ_obj2nid(cms->contentType) != NID_id_smime_ct_timestampedData)
		{
		CMSerr(CMS_F_CMS_GET0_TIMESTAMPED,
				CMS_R_CONTENT_TYPE_NOT_TIMESTAMPED_DATA);
		return NULL;
		}
	return cms->d.timestampedData;
	}

/*
 * Extracts the inner
 * TimeStampTokenEvidence ::= SEQUENCE SIZE(1..MAX) OF TimeStampAndCRL
 */

STACK_OF(CMS_TimeStampAndCRL) *cms_get0_timeStampTokenChain(
		CMS_ContentInfo *cms)
	{
	CMS_Evidence *evidence;
	evidence = cms_get0_timestamped(cms)->temporalEvidence;
	if (!evidence)
		return NULL;
 	return evidence->d.tstEvidence;
	}

static CMS_TSTInfo *cms_get0_tstInfo(CMS_ContentInfo *token)
	{
	return cms_tstInfo_decode(token);
	}

static CMS_MessageImprint *cms_TSTInfo_get0_msgImprint(CMS_TSTInfo *tstInfo)
	{
	return tstInfo->messageImprint;
	}

static X509_ALGOR *cms_MessageImprint_get0_hashAlgorithm(CMS_MessageImprint *messageImprint)
	{
	return messageImprint->hashAlgorithm;
	}

static ASN1_OCTET_STRING *cms_MessageImprint_get0_hashedMessage(CMS_MessageImprint *messageImprint)
	{
	return messageImprint->hashedMessage;
	}

int cms_check_dataUri(CMS_ContentInfo *cms)
	{
	ASN1_IA5STRING *dataUri = cms->d.timestampedData->dataUri;
	if (!dataUri)
		return 0;
	return 1;
	}

static int cms_Token_signature_verify(CMS_ContentInfo *token,
		STACK_OF(X509) *certs, X509_STORE *store, unsigned int flags)
	{
	/* token sanity check */
	if (!token)
		{
		CMSerr(CMS_F_CMS_TOKEN_SIGNATURE_VERIFY, CMS_R_NULL_TIMESTAMP_TOKEN);
		return 0;
		}

	/* sign verify using the previous CMS implementation */
	if (!CMS_verify(token, certs, store, NULL, NULL, flags))
		return 0;

	return 1;
	}

static int cms_compute_digest(CMS_ContentInfo *cms, CMS_TSTInfo *tstInfo,
		X509_ALGOR **digestAlgorithm,
		unsigned char **digest, unsigned *digestLength)
	{
	CMS_MessageImprint *messageImprint;
	X509_ALGOR *tokenDigestAlgorithm;
	const EVP_MD *md;
	EVP_MD_CTX mdContext;
	ASN1_OCTET_STRING **data;
//	unsigned char buffer[4096];
	int length = 0;

	messageImprint = cms_TSTInfo_get0_msgImprint(tstInfo);
	tokenDigestAlgorithm = cms_MessageImprint_get0_hashAlgorithm(messageImprint);
	data = CMS_get0_content(cms);

	/* Return the MD algorithm of the response. */
	*digestAlgorithm = X509_ALGOR_dup(tokenDigestAlgorithm);
	if (!(*digestAlgorithm))
		goto err;

	/* Getting the MD object. */
	md = EVP_get_digestbyobj((*digestAlgorithm)->algorithm);
	if (!md)
		{
		CMSerr(CMS_F_CMS_COMPUTE_DIGEST, CMS_R_UNKNOWN_DIGEST_ALGORIHM);
		goto err;
		}

	/* Compute message digest. */
	length = EVP_MD_size(md);
	if (length < 0)
	    goto err;
	*digestLength = length;

	if (!(*digest = OPENSSL_malloc(*digestLength)))
		{
		CMSerr(CMS_F_CMS_COMPUTE_DIGEST, ERR_R_MALLOC_FAILURE);
		goto err;
		}

	if (!EVP_DigestInit(&mdContext, md))
		goto err;

//		while ((length = BIO_read(data, buffer, sizeof(buffer))) > 0)
//			{
	if (!EVP_DigestUpdate(&mdContext, (*data)->data, (*data)->length))
		goto err;
//			}
	if (!EVP_DigestFinal(&mdContext, *digest, NULL))
		goto err;

	return 1;

	err:

	X509_ALGOR_free(*digestAlgorithm);
	OPENSSL_free(*digest);
	*digestLength = 0;
	return 0;
	}

static int cms_Token_digest_verify(CMS_TSTInfo *tstInfo,
		unsigned char *digest, unsigned digestLength)
	{
	CMS_MessageImprint *messageImprint;
	X509_ALGOR *tokenDigestAlgorithm;
	ASN1_OCTET_STRING *tokenDigest;

	messageImprint = cms_TSTInfo_get0_msgImprint(tstInfo);
	tokenDigestAlgorithm = cms_MessageImprint_get0_hashAlgorithm(messageImprint);
	tokenDigest = cms_MessageImprint_get0_hashedMessage(messageImprint);

	if (digestLength != (unsigned)tokenDigest->length)
		{
		CMSerr(CMS_F_CMS_TOKEN_DIGEST_VERIFY, CMS_R_NO_MATCHING_DIGEST);
		return 0;
		}
	if (memcmp(digest, tokenDigest->data, digestLength) != 0)
		{
		CMSerr(CMS_F_CMS_TOKEN_DIGEST_VERIFY, CMS_R_NO_MATCHING_DIGEST);
		return 0;
		}
	return 1;
	}

int cms_token_verify(CMS_ContentInfo *cms, CMS_ContentInfo *token,
		STACK_OF(X509) *certs, X509_STORE *store, unsigned int flags)
	{
	X509_ALGOR *digestAlgorithm = NULL;
	unsigned char *digest = NULL;
	unsigned digestLength = 0;
	CMS_TSTInfo *tstInfo;

	/* tstInfo get and version check */
	tstInfo = cms_get0_tstInfo(token);
	if (ASN1_INTEGER_get(tstInfo->version) != 1)
		{
		CMSerr(CMS_F_CMS_TOKEN_VERIFY, CMS_R_UNSUPPORTED_VERSION);
		goto err;
		}

	/* verify the signature */
	if (!cms_Token_signature_verify(token, certs, store, flags))
		goto err;

	/* compute the hash of the content */
	if (!cms_compute_digest(cms, tstInfo, &digestAlgorithm,
			&digest, &digestLength))
		goto err;

	/* verify the hash matching */
	if (!cms_Token_digest_verify(tstInfo, digestAlgorithm, digest, digestLength))
		goto err;

	return 1;

	err:

	if (tstInfo)
		CMS_TSTInfo_free(tstInfo);
	return 0;
	}

CMS_ContentInfo *cms_TimeStampedData_create(BIO *content, BIO *response,
		unsigned char *dataUri, STACK_OF(X509) *certs, X509_STORE *store, unsigned int flags)
	{
	CMS_ContentInfo *cms;
	CMS_TimestampedData *tsd;

	cms = CMS_ContentInfo_new();
	if (!cms)
		return NULL;

	tsd = M_ASN1_new_of(CMS_TimestampedData);
	if (!tsd)
		goto err;

	cms->contentType = OBJ_nid2obj(NID_id_smime_ct_timestampedData);
	cms->d.timestampedData = tsd;

	tsd->version = M_ASN1_INTEGER_new();
	if (!ASN1_INTEGER_set(tsd->version, 1))
		goto err;

	if (dataUri)
		{
		tsd->dataUri = M_ASN1_IA5STRING_new();
		if (!ASN1_STRING_set(tsd->dataUri, dataUri, strlen(dataUri)))
			goto err;
		}

	err:

	if (tsd)
		M_ASN1_free_of(tsd, CMS_TimestampedData);

	if (cms)
		CMS_ContentInfo_free(cms);

	}

