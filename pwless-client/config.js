let config_ = undefined;
export function configure(config) {
    if (config) {
        config_ = { ...config, storage: config.storage ?? localStorage };
        config_.debug?.("Configuration loaded:", config);
    }
    else {
        if (!config_) {
            throw new Error("Call configure(config) first");
        }
    }
    return config_;
}
export function configureFromAmplify(amplifyConfig) {
    const { region, userPoolId, userPoolWebClientId } = isAmplifyConfig(amplifyConfig)
        ? amplifyConfig.Auth
        : amplifyConfig;
    if (typeof region !== "string") {
        throw new Error("Invalid Amplify configuration provided: invalid or missing region");
    }
    if (typeof userPoolId !== "string") {
        throw new Error("Invalid Amplify configuration provided: invalid or missing userPoolId");
    }
    if (typeof userPoolWebClientId !== "string") {
        throw new Error("Invalid Amplify configuration provided: invalid or missing userPoolWebClientId");
    }
    configure({
        cognitoIdpEndpoint: region,
        userPoolId,
        clientId: userPoolWebClientId,
    });
    return {
        with: (config) => {
            return configure({
                cognitoIdpEndpoint: region,
                userPoolId,
                clientId: userPoolWebClientId,
                ...config,
            });
        },
    };
}
function isAmplifyConfig(c) {
    return !!c && typeof c === "object" && "Auth" in c;
}
