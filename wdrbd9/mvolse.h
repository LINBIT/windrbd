#ifndef MVF_MVOLSE_H
#define MVF_MVOLSE_H

#define	MVOL_TOKEN_SOURCE_LENGTH		8

typedef struct _MVOL_TOKEN_SOURCE
{
    CCHAR						SourceName[MVOL_TOKEN_SOURCE_LENGTH];
    LUID						SourceIdentifier;
} MVOL_TOKEN_SOURCE, *PMVOL_TOKEN_SOURCE;

typedef struct _MVOL_TOKEN_CONTROL
{
    LUID						TokenId;
    LUID						AuthenticationId;
    LUID						ModifiedId;
    MVOL_TOKEN_SOURCE			TokenSource;
} MVOL_TOKEN_CONTROL, *PMVOL_TOKEN_CONTROL;

typedef struct _MVOL_SECURITY_CLIENT_CONTEXT
{
    SECURITY_QUALITY_OF_SERVICE	SecurityQos;
    PACCESS_TOKEN				ClientToken;
    BOOLEAN						DirectlyAccessClientToken;
    BOOLEAN						DirectAccessEffectiveOnly;
    BOOLEAN						ServerIsRemote;
    MVOL_TOKEN_CONTROL			ClientTokenControl;
} MVOL_SECURITY_CLIENT_CONTEXT, *PMVOL_SECURITY_CLIENT_CONTEXT;
#endif // MVF_MVOLSE_H