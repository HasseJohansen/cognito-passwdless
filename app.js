import { revokeToken } from './pwless-client/cognito-api.js';
import { scheduleRefresh, refreshTokens } from './pwless-client/refresh.js';
import { Passwordless } from './pwless-client/index.js';
import { requestSignInLink, signInWithLink } from './pwless-client/magic-link.js';
import { retrieveTokens, storeTokens } from './pwless-client/storage.js';
import { configure } from './pwless-client/config.js';
import { fido2CreateCredential, fido2ListCredentials, fido2DeleteCredential, authenticateWithFido2 } from './pwless-client/fido2.js';
import { parseJwtPayload } from "./pwless-client/util.js";

const clientId = '<clientid>';
const fido2BaseUrl = '<api gw endpoint>';

Passwordless.configure({
    cognitoIdpEndpoint: 'eu-west-1',
    clientId: clientId,
    fido2: {
        baseUrl: fido2BaseUrl,
        authenticatorSelection: {
            userVerification: "required",
        },
    },
    debug: console.debug,
})


async function isLoggedInOrNewLogin() {
    var tokens = await retrieveTokens();
    const { clientId, debug, storage } = configure();
    
    // If accesstoken etc is expired try to refresh from refreshtoken
    if (tokens?.refreshToken && tokens?.expireAt <= Date.now()) {
        refreshFromRefreshToken();
    }

    if (tokens && tokens?.expireAt >= Date.now()) {
        scheduleTokenRefresh();
        return true;
    }

    if (storage.getItem(`Passwordless.${clientId}.fido`)) {
	document.getElementById('pkLoginLabel').innerHTML = `Login with Passkey ${JSON.parse(storage.getItem(`Passwordless.${clientId}.fido`)).email}`;
	document.getElementById('pkLoginDialog').show();
    } else {
        await signInWithLink();
    }
}

function scheduleTokenRefresh() {
    scheduleRefresh({
        tokensCb: (newTokens) =>
          newTokens &&
          storeTokens(newTokens)
      })
}

async function refreshFromRefreshToken() {
    const { clientId, debug, storage } = configure();
    const tokens = await retrieveTokens();
    try {
        await refreshTokens({
            tokensCb: (newTokens) =>
            newTokens &&
            storeTokens(newTokens)
        })
    } catch(err) {
        if (err == 'NotAuthorizedException: Refresh Token has expired') {
            console.log('Removing expired refresh token');
            storage.removeItem(`CognitoIdentityServiceProvider.${clientId}.${tokens.username}.refreshToken`);
        }
    }
}

function loginSubmitHandler(evt) {
	var authenticationData = {
		email: document.getElementById("emailfield").value,
	};
    
    const { signInLinkRequested } = requestSignInLink({ 
        usernameOrAlias: authenticationData.email,
        statusCb: console.log
    });
}

async function signOutHandler() {
    console.log("Signing out");
    const { clientId, debug, storage } = configure();
    const tokens = await retrieveTokens();
  
    storage.removeItem(`CognitoIdentityServiceProvider.${clientId}.${tokens.username}.accessToken`);
    storage.removeItem(`CognitoIdentityServiceProvider.${clientId}.${tokens.username}.idToken`);
    storage.removeItem(`CognitoIdentityServiceProvider.${clientId}.${tokens.username}.refreshToken`);
    storage.removeItem(`CognitoIdentityServiceProvider.${clientId}.${tokens.username}.tokenScopesString`);
    storage.removeItem(`CognitoIdentityServiceProvider.${clientId}.${tokens.username}.userData`);
    storage.removeItem(`CognitoIdentityServiceProvider.${clientId}.LastAuthUser`);
    storage.removeItem(`Passwordless.${clientId}.${tokens.username}.expireAt`);
    storage.removeItem(`Passwordless.${clientId}.${tokens.username}.refreshTokens`);
    await revokeToken({
        abort: undefined, // if we've come this far, let this proceed
        refreshToken: tokens.refreshToken,
    });
    document.location.reload()
}

async function showPasskeys() {
    const credentials = await fido2ListCredentials();
    const select = document.getElementById('selectPasskey');
    for (var authenticator of credentials.authenticators) {
        let element = document.createElement('option');
        element.textContent = `${authenticator.friendlyName}`;
        select.append(element);
    }
    const dialog = document.getElementById('passkeysDialog')
    addInputFieldToParrent('Passkey Name', dialog);
    addButtonToParrent('Create Passkey', dialog);
    addButtonToParrent('Back', dialog);
    
    const passform = select.parentElement;
    addButtonToParrent('Delete', passform);

    document.getElementById('loggedInDialog').close();
    document.getElementById('passkeysDialog').show();

    document.getElementById('CreatePasskey').addEventListener('click', createPasskey);
    document.getElementById('Delete').addEventListener('click', deletePasskey);
}

function addButtonToParrent(btnName, parent) {
    let button = document.createElement('button');
    button.setAttribute('class', 'btn');
    button.setAttribute('id', btnName.replaceAll(' ',''));
    button.textContent = btnName;
    parent.append(button);
}

function addInputFieldToParrent(inputName, parent) {
    let input = document.createElement('input');
    input.setAttribute('type', 'text');
    input.setAttribute('id', inputName.replaceAll(' ',''));
    input.setAttribute('name', inputName.replaceAll(' ',''));
    input.textContent = inputName;
    parent.append(input);
}

async function createPasskey() {
    const { clientId, debug, storage } = configure();
    console.log(document.getElementById('PasskeyName').value);
    let fidoCredential = await fido2CreateCredential({ friendlyName: document.getElementById('PasskeyName').value});
    const tokens = await retrieveTokens();
    const { sub, email, "cognito:username": username, } = parseJwtPayload(tokens.idToken);
    storage.setItem(`Passwordless.${clientId}.fido`, JSON.stringify({
	username: username,
	email: email,
	credential: fidoCredential 
    }));
}

async function deletePasskey() {
    const select = document.getElementById('selectPasskey');
    const selected = select.options[select.selectedIndex].text;
    const authenticators = (await fido2ListCredentials()).authenticators;
    for (let authenticator of authenticators) {
        if (authenticator.friendlyName == selected) {
            fido2DeleteCredential({ credentialId: authenticator.credentialId });
        }
    }
}

async function authenticateWithPasskey() {
    const { clientId, debug, storage } = configure();
    
    const signingIn = authenticateWithFido2({
	username: JSON.parse(storage.getItem(`Passwordless.${clientId}.fido`)).username,
    });
    signingIn.signedIn.then(() => { document.location.reload(); });
}

document.getElementById('loginForm').addEventListener('submit', loginSubmitHandler);
document.getElementById('loggedInButton').addEventListener('click', signOutHandler);
document.getElementById('passkeysButton').addEventListener('click', showPasskeys);
document.getElementById('pkLoginButton').addEventListener('click', authenticateWithPasskey);

if (await isLoggedInOrNewLogin()) {
    document.getElementById('loginDialog').close();
    document.getElementById('loggedInDialog').show();
} else {
    document.getElementById('loggedInDialog').close();
    if (! document.getElementById('pkLoginDialog').open) {
	document.getElementById('loginDialog').show();
    }
}

console.log(`Login status: ${await isLoggedInOrNewLogin()}`);
