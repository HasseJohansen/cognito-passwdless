/**
 * Copyright Amazon.com, Inc. and its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"). You
 * may not use this file except in compliance with the License. A copy of
 * the License is located at
 *
 *     http://aws.amazon.com/apache2.0/
 *
 * or in the "license" file accompanying this file. This file is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
 * ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */
import { parseJwtPayload, throwIfNot2xx } from "./util.js";
import { configure } from "./config.js";
import { retrieveTokens } from "./storage.js";
const AWS_REGION_REGEXP = /^[a-z]{2}-[a-z]+-\d$/;
export function isErrorResponse(obj) {
    return (!!obj && typeof obj === "object" && "__type" in obj && "message" in obj);
}
export function assertIsNotErrorResponse(obj) {
    if (isErrorResponse(obj)) {
        const err = new Error();
        err.name = obj.__type;
        err.message = obj.message;
        throw err;
    }
}
export function assertIsNotChallengeResponse(obj) {
    if (isChallengeResponse(obj)) {
        throw new Error(`Unexpected challenge: ${obj.ChallengeName}`);
    }
}
export function assertIsNotAuthenticatedResponse(obj) {
    if (isAuthenticatedResponse(obj)) {
        throw new Error("Unexpected authentication response");
    }
}
export function isChallengeResponse(obj) {
    return (!!obj &&
        typeof obj === "object" &&
        "ChallengeName" in obj &&
        "ChallengeParameters" in obj);
}
export function assertIsChallengeResponse(obj) {
    assertIsNotErrorResponse(obj);
    assertIsNotAuthenticatedResponse(obj);
    if (!isChallengeResponse(obj)) {
        throw new Error("Expected challenge response");
    }
}
export function isAuthenticatedResponse(obj) {
    return !!obj && typeof obj === "object" && "AuthenticationResult" in obj;
}
export function assertIsAuthenticatedResponse(obj) {
    assertIsNotErrorResponse(obj);
    assertIsNotChallengeResponse(obj);
    if (!isAuthenticatedResponse(obj)) {
        throw new Error("Expected authentication response");
    }
}
export function assertIsSignInResponse(obj) {
    assertIsNotErrorResponse(obj);
    if (!isAuthenticatedResponse(obj) && !isChallengeResponse(obj)) {
        throw new Error("Expected sign-in response");
    }
}
export async function initiateAuth({ authflow, authParameters, clientMetadata, abort, }) {
    const config = configure();
    return fetch(config.cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
        ? `https://cognito-idp.${config.cognitoIdpEndpoint}.amazonaws.com/`
        : config.cognitoIdpEndpoint, {
        signal: abort,
        headers: {
            "x-amz-target": "AWSCognitoIdentityProviderService.InitiateAuth",
            "content-type": "application/x-amz-json-1.1",
            ...config.proxyApiHeaders,
        },
        method: "POST",
        body: JSON.stringify({
            AuthFlow: authflow,
            ClientId: config.clientId,
            AuthParameters: authParameters,
            ClientMetadata: clientMetadata,
        }),
    }).then(extractInitiateAuthResponse(authflow));
}
export async function respondToAuthChallenge({ challengeName, challengeResponses, session, clientMetadata, abort, }) {
    const config = configure();
    return fetch(config.cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
        ? `https://cognito-idp.${config.cognitoIdpEndpoint}.amazonaws.com/`
        : config.cognitoIdpEndpoint, {
        headers: {
            "x-amz-target": "AWSCognitoIdentityProviderService.RespondToAuthChallenge",
            "content-type": "application/x-amz-json-1.1",
            ...config.proxyApiHeaders,
        },
        method: "POST",
        body: JSON.stringify({
            ChallengeName: challengeName,
            ChallengeResponses: challengeResponses,
            ClientId: config.clientId,
            Session: session,
            ClientMetadata: clientMetadata,
        }),
        signal: abort,
    }).then(extractChallengeResponse);
}
export async function revokeToken({ refreshToken, abort, }) {
    const config = configure();
    return await fetch(config.cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
        ? `https://cognito-idp.${config.cognitoIdpEndpoint}.amazonaws.com/`
        : config.cognitoIdpEndpoint, {
        headers: {
            "x-amz-target": "AWSCognitoIdentityProviderService.RevokeToken",
            "content-type": "application/x-amz-json-1.1",
            ...config.proxyApiHeaders,
        },
        method: "POST",
        body: JSON.stringify({
            Token: refreshToken,
            ClientId: config.clientId,
        }),
        signal: abort,
    }).then(throwIfNot2xx);
}
export async function getId({ identityPoolId, abort, }) {
    const config = configure();
    const identityPoolRegion = identityPoolId.split(":")[0];
    const { idToken } = (await retrieveTokens()) ?? {};
    if (!idToken) {
        throw new Error("Missing ID token");
    }
    const iss = new URL(parseJwtPayload(idToken)["iss"]);
    return fetch(`https://cognito-identity.${identityPoolRegion}.amazonaws.com/`, {
        signal: abort,
        headers: {
            "x-amz-target": "AWSCognitoIdentityService.GetId",
            "content-type": "application/x-amz-json-1.1",
            ...config.proxyApiHeaders,
        },
        method: "POST",
        body: JSON.stringify({
            IdentityPoolId: identityPoolId,
            Logins: {
                [`${iss.hostname}${iss.pathname}`]: idToken,
            },
        }),
    })
        .then(throwIfNot2xx)
        .then((res) => res.json());
}
export async function getCredentialsForIdentity({ identityId, abort, }) {
    const config = configure();
    const identityPoolRegion = identityId.split(":")[0];
    const { idToken } = (await retrieveTokens()) ?? {};
    if (!idToken) {
        throw new Error("Missing ID token");
    }
    const iss = new URL(parseJwtPayload(idToken)["iss"]);
    return fetch(`https://cognito-identity.${identityPoolRegion}.amazonaws.com/`, {
        signal: abort,
        headers: {
            "x-amz-target": "AWSCognitoIdentityService.GetCredentialsForIdentity",
            "content-type": "application/x-amz-json-1.1",
            ...config.proxyApiHeaders,
        },
        method: "POST",
        body: JSON.stringify({
            IdentityId: identityId,
            Logins: {
                [`${iss.hostname}${iss.pathname}`]: idToken,
            },
        }),
    })
        .then(throwIfNot2xx)
        .then((res) => res.json());
}
export async function signUp({ username, password, userAttributes, clientMetadata, validationData, abort, }) {
    const config = configure();
    await fetch(config.cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
        ? `https://cognito-idp.${config.cognitoIdpEndpoint}.amazonaws.com/`
        : config.cognitoIdpEndpoint, {
        headers: {
            "x-amz-target": "AWSCognitoIdentityProviderService.SignUp",
            "content-type": "application/x-amz-json-1.1",
            ...config.proxyApiHeaders,
        },
        method: "POST",
        body: JSON.stringify({
            Username: username,
            Password: password,
            UserAttributes: userAttributes &&
                userAttributes.map(({ name, value }) => ({
                    Name: name,
                    Value: value,
                })),
            ValidationData: validationData &&
                validationData.map(({ name, value }) => ({
                    Name: name,
                    Value: value,
                })),
            ClientMetadata: clientMetadata,
            ClientId: config.clientId,
        }),
        signal: abort,
    }).then(throwIfNot2xx);
}
export async function updateUserAttributes({ clientMetadata, userAttributes, abort, }) {
    const config = configure();
    const tokens = await retrieveTokens();
    await fetch(config.cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
        ? `https://cognito-idp.${config.cognitoIdpEndpoint}.amazonaws.com/`
        : config.cognitoIdpEndpoint, {
        headers: {
            "x-amz-target": "AWSCognitoIdentityProviderService.UpdateUserAttributes",
            "content-type": "application/x-amz-json-1.1",
            ...config.proxyApiHeaders,
        },
        method: "POST",
        body: JSON.stringify({
            AccessToken: tokens?.accessToken,
            ClientMetadata: clientMetadata,
            UserAttributes: userAttributes.map(({ name, value }) => ({
                Name: name,
                Value: value,
            })),
        }),
        signal: abort,
    }).then(throwIfNot2xx);
}
export async function getUserAttributeVerificationCode({ attributeName, clientMetadata, abort, }) {
    const config = configure();
    const tokens = await retrieveTokens();
    await fetch(config.cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
        ? `https://cognito-idp.${config.cognitoIdpEndpoint}.amazonaws.com/`
        : config.cognitoIdpEndpoint, {
        headers: {
            "x-amz-target": "AWSCognitoIdentityProviderService.GetUserAttributeVerificationCode",
            "content-type": "application/x-amz-json-1.1",
            ...config.proxyApiHeaders,
        },
        method: "POST",
        body: JSON.stringify({
            AccessToken: tokens?.accessToken,
            ClientMetadata: clientMetadata,
            AttributeName: attributeName,
        }),
        signal: abort,
    }).then(throwIfNot2xx);
}
export async function verifyUserAttribute({ attributeName, code, abort, }) {
    const config = configure();
    const tokens = await retrieveTokens();
    await fetch(config.cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
        ? `https://cognito-idp.${config.cognitoIdpEndpoint}.amazonaws.com/`
        : config.cognitoIdpEndpoint, {
        headers: {
            "x-amz-target": "AWSCognitoIdentityProviderService.VerifyUserAttribute",
            "content-type": "application/x-amz-json-1.1",
            ...config.proxyApiHeaders,
        },
        method: "POST",
        body: JSON.stringify({
            AccessToken: tokens?.accessToken,
            AttributeName: attributeName,
            Code: code,
        }),
        signal: abort,
    }).then(throwIfNot2xx);
}
export async function setUserMFAPreference({ smsMfaSettings, softwareTokenMfaSettings, abort, }) {
    const config = configure();
    const tokens = await retrieveTokens();
    await fetch(config.cognitoIdpEndpoint.match(AWS_REGION_REGEXP)
        ? `https://cognito-idp.${config.cognitoIdpEndpoint}.amazonaws.com/`
        : config.cognitoIdpEndpoint, {
        headers: {
            "x-amz-target": "AWSCognitoIdentityProviderService.SetUserMFAPreference",
            "content-type": "application/x-amz-json-1.1",
            ...config.proxyApiHeaders,
        },
        method: "POST",
        body: JSON.stringify({
            AccessToken: tokens?.accessToken,
            SMSMfaSettings: smsMfaSettings && {
                Enabled: smsMfaSettings.enabled,
                PreferredMfa: smsMfaSettings.preferred,
            },
            SoftwareTokenMfaSettings: softwareTokenMfaSettings && {
                Enabled: softwareTokenMfaSettings.enabled,
                PreferredMfa: softwareTokenMfaSettings.preferred,
            },
        }),
        signal: abort,
    }).then(throwIfNot2xx);
}
export async function handleAuthResponse({ authResponse, username, smsMfaCode, newPassword, customChallengeAnswer, clientMetadata, abort, }) {
    const { debug } = configure();
    for (;;) {
        if (isAuthenticatedResponse(authResponse)) {
            return {
                idToken: authResponse.AuthenticationResult.IdToken,
                accessToken: authResponse.AuthenticationResult.AccessToken,
                expireAt: new Date(Date.now() + authResponse.AuthenticationResult.ExpiresIn * 1000),
                refreshToken: authResponse.AuthenticationResult.RefreshToken,
                username,
            };
        }
        const responseParameters = {};
        if (authResponse.ChallengeName === "SMS_MFA") {
            if (!smsMfaCode)
                throw new Error("Missing MFA Code");
            responseParameters.SMS_MFA_CODE = await smsMfaCode();
        }
        else if (authResponse.ChallengeName === "NEW_PASSWORD_REQUIRED") {
            if (!newPassword)
                throw new Error("Missing new password");
            responseParameters.NEW_PASSWORD = await newPassword();
        }
        else if (authResponse.ChallengeName === "CUSTOM_CHALLENGE") {
            if (!customChallengeAnswer)
                throw new Error("Missing custom challenge answer");
            responseParameters.ANSWER = await customChallengeAnswer();
        }
        else {
            throw new Error(`Unsupported challenge: ${authResponse.ChallengeName}`);
        }
        debug?.(`Invoking respondToAuthChallenge ...`);
        const nextAuthResult = await respondToAuthChallenge({
            challengeName: authResponse.ChallengeName,
            challengeResponses: {
                USERNAME: username,
                ...responseParameters,
            },
            clientMetadata,
            session: authResponse.Session,
            abort,
        });
        debug?.(`Response from respondToAuthChallenge:`, nextAuthResult);
        authResponse = nextAuthResult;
    }
}
function extractInitiateAuthResponse(authflow) {
    return async (res) => {
        await throwIfNot2xx(res);
        const body = (await res.json());
        if (authflow === "REFRESH_TOKEN_AUTH") {
            assertIsAuthenticatedResponse(body);
        }
        else {
            assertIsSignInResponse(body);
        }
        return body;
    };
}
async function extractChallengeResponse(res) {
    await throwIfNot2xx(res);
    const body = (await res.json());
    assertIsSignInResponse(body);
    return body;
}
