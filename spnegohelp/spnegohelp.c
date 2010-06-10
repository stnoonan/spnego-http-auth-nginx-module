/* -----------------------------------------------------------------------------
 * spnegohelp.c defines RFC 2478 SPNEGO GSS-API mechanism APIs.
 *
 * Author: Frank Balluffi
 *
 * Copyright (C) 2002-2003 All rights reserved.
 * -----------------------------------------------------------------------------
 */

#include "spnegohelp.h"
#include "spnego.h"

#include <stdlib.h>

int makeNegTokenTarg (const unsigned char *  kerberosToken,
                      size_t                 kerberosTokenLength,
                      const unsigned char ** negTokenTarg,
                      size_t *               negTokenTargLength)
{
    SPNEGO_TOKEN_HANDLE hSpnegoToken = NULL;
    int                 rc1          = 1;
    int                 rc2          = SPNEGO_E_SUCCESS;

    /* Check arguments. */

    if (!kerberosToken ||
        !negTokenTarg  ||
        !negTokenTargLength)
        return 10;

    /* Does IIS reply with 1.2.840.48018.1.2.2 or 1.2.840.113554.1.2.2? */

    /* Does IIS always reply with accept_completed? */

    /* IIS does not include a MIC. */

    rc2 = spnegoCreateNegTokenTarg (spnego_mech_oid_Kerberos_V5_Legacy,
                                    spnego_negresult_success,
                                    (unsigned char *) kerberosToken,
                                    kerberosTokenLength,
                                    NULL,
                                    0,
                                    &hSpnegoToken);

    if (rc2 != SPNEGO_E_SUCCESS)
    {
        rc1 = abs(rc2)+100;
        goto cleanup;
    }

    /* Get NegTokenTarg length. */

    rc2 = spnegoTokenGetBinary (hSpnegoToken,
                                NULL,
                                (unsigned long*) negTokenTargLength);

    if (rc2 != SPNEGO_E_BUFFER_TOO_SMALL)
    {
        rc1 = abs(rc2)+200;
        goto cleanup;
    }

    *negTokenTarg = malloc (*negTokenTargLength);

    if (!*negTokenTarg)
    {
        rc1 = abs(rc2)+300;
        goto cleanup;
    }

    /* Get NegTokenTarg data. */

    rc2 = spnegoTokenGetBinary (hSpnegoToken,
                              (unsigned char *) *negTokenTarg,
                              (unsigned long*) negTokenTargLength);


    if (rc2 != SPNEGO_E_SUCCESS)
    {
        rc1 = abs(rc2)+400;
        goto error;
    }

    rc1 = 0;

    goto cleanup;

error:

    if (*negTokenTarg)
    {
        free ((unsigned char *) *negTokenTarg);
        *negTokenTarg = NULL;
        *negTokenTargLength = 0;
    }

cleanup:

    if (hSpnegoToken)
        spnegoFreeData (hSpnegoToken);

    LOG(("makeNegTokenTarg returned %d\n",rc1));
    return rc1;
}

int parseNegTokenInit (const unsigned char *  negTokenInit,
                       size_t                 negTokenInitLength,
                       const unsigned char ** kerberosToken,
                       size_t *               kerberosTokenLength)
{
    SPNEGO_TOKEN_HANDLE hSpnegoToken = NULL;
    int                 index        = -1;
    int                 rc1          = 1;
    int                 rc2          = SPNEGO_E_SUCCESS;
    unsigned char       reqFlags     = 0;
    int                 tokenType    = 0;

    /* Check arguments. */

    if (!negTokenInit  ||
        !kerberosToken ||
        !kerberosTokenLength)
        return 10;

    /* Decode SPNEGO token. */

    rc2 = spnegoInitFromBinary ((unsigned char *) negTokenInit,
                                negTokenInitLength,
                                &hSpnegoToken);

    if (rc2 != SPNEGO_E_SUCCESS)
    {
        rc1 = abs(rc2)+100;
        goto cleanup;
    }

    /* Check for negTokenInit choice. */

    rc2 = spnegoGetTokenType (hSpnegoToken,
                              &tokenType);

    if (rc2 != SPNEGO_E_SUCCESS)
    {
        rc1 = abs(rc2)+200;
        goto cleanup;
    }

    if (tokenType != SPNEGO_TOKEN_INIT)
    {
        rc1 = abs(rc2)+300;
        goto cleanup;
    }

   /*
    Check that first mechType is 1.2.840.113554.1.2.2 or 1.2.840.48018.1.2.2.
    */

   /*
    IE seems to reply with 1.2.840.48018.1.2.2 and then 1.2.840.113554.1.2.2.
    */

    rc2 = spnegoIsMechTypeAvailable (hSpnegoToken,
                                     spnego_mech_oid_Kerberos_V5_Legacy,
                                     &index);

    if (rc2 != SPNEGO_E_SUCCESS ||
        index != 0)
    {
        rc2 = spnegoIsMechTypeAvailable (hSpnegoToken,
                                         spnego_mech_oid_Kerberos_V5,
                                         &index);

        if (rc2 != SPNEGO_E_SUCCESS ||
            index != 0)
        {
            rc1 = abs(rc2)+400;
            goto cleanup;
        }
    }

    /* Check for no reqFlags. */

    /* Does IE ever send reqFlags? */

    rc2 = spnegoGetContextFlags (hSpnegoToken,
                                 &reqFlags);

    if (rc2 == SPNEGO_E_SUCCESS)
    {
        rc1 = abs(rc2)+500;
        goto cleanup;
    }

    /* Get mechanism token length. */

    rc2 = spnegoGetMechToken (hSpnegoToken,
                              NULL,
                              (unsigned long*) kerberosTokenLength);

    if (rc2 != SPNEGO_E_BUFFER_TOO_SMALL)
    {
        rc1 = abs(rc2)+600;
        goto cleanup;
    }

    *kerberosToken = malloc (*kerberosTokenLength);

    if (!*kerberosToken)
    {
        rc1 = abs(rc2)+700;
        goto cleanup;
    }

    /* Get mechanism token data. */

    rc2 = spnegoGetMechToken (hSpnegoToken,
                              (unsigned char *) *kerberosToken,
                              (unsigned long*) kerberosTokenLength);

    if (rc2 != SPNEGO_E_SUCCESS)
    {
        rc1 = abs(rc2)+800;
        goto error;
    }

    /* According to Microsoft, IE does not send a MIC. */

    rc1 = 0;

    goto cleanup;

error:

    if (*kerberosToken)
    {
        free ((unsigned char *) *kerberosToken);
        *kerberosToken = NULL;
        *kerberosTokenLength = 0;
    }

cleanup:

    if (hSpnegoToken)
        spnegoFreeData (hSpnegoToken);

    LOG(("parseNegTokenInit returned %d\n",rc1));
    return rc1;
}
