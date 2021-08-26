﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web.InstanceDiscovery;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.Identity.Web.Resource
{
    /// <summary>
    /// Generic class that validates token issuer from the provided Azure AD authority.
    /// </summary>
    public class AadIssuerValidator
    {
        internal AadIssuerValidator(
            IOptions<AadIssuerValidatorOptions> aadIssuerValidatorOptions,
            IHttpClientFactory httpClientFactory,
            string aadAuthority)
        {
            AadIssuerValidatorOptions = aadIssuerValidatorOptions;
            HttpClientFactory = httpClientFactory;
            AadAuthority = aadAuthority.TrimEnd('/');
        }

        private IOptions<AadIssuerValidatorOptions> AadIssuerValidatorOptions { get; }
        private IHttpClientFactory HttpClientFactory { get; }
        internal string? AadIssuerV1 { get; set; }
        internal string? AadIssuerV2 { get; set; }
        internal string AadAuthority { get; set; }

        /// <summary>
        /// Validate the issuer for multi-tenant applications of various audiences (Work and School accounts, or Work and School accounts +
        /// Personal accounts).
        /// </summary>
        /// <param name="actualIssuer">Issuer to validate (will be tenanted).</param>
        /// <param name="securityToken">Received security token.</param>
        /// <param name="validationParameters">Token validation parameters.</param>
        /// <remarks>The issuer is considered as valid if it has the same HTTP scheme and authority as the
        /// authority from the configuration file, has a tenant ID, and optionally v2.0 (this web API
        /// accepts both V1 and V2 tokens).</remarks>
        /// <returns>The <c>issuer</c> if it's valid, or otherwise <c>SecurityTokenInvalidIssuerException</c> is thrown.</returns>
        /// <exception cref="ArgumentNullException"> if <paramref name="securityToken"/> is null.</exception>
        /// <exception cref="ArgumentNullException"> if <paramref name="validationParameters"/> is null.</exception>
        /// <exception cref="SecurityTokenInvalidIssuerException">if the issuer is invalid. </exception>
        public string Validate(
            string actualIssuer,
            SecurityToken securityToken,
            TokenValidationParameters validationParameters)
        {
            if (string.IsNullOrEmpty(actualIssuer))
            {
                throw new ArgumentNullException(nameof(actualIssuer));
            }

            if (securityToken == null)
            {
                throw new ArgumentNullException(nameof(securityToken));
            }

            if (validationParameters == null)
            {
                throw new ArgumentNullException(nameof(validationParameters));
            }

            string tenantId = GetTenantIdFromToken(securityToken);
            if (string.IsNullOrWhiteSpace(tenantId))
            {
                throw new SecurityTokenInvalidIssuerException(IDWebErrorMessage.TenantIdClaimNotPresentInToken);
            }

            // if the user provides an explicit list of valid issuer(s), <assumption> we should use only their list
            // and skip any metadata discovery of issuer
            // we could get the issuer data from metadata and ignore that one (if templated, as would be expected in a multitenant app)
            // but we'd pay that tax the first time, then store them in the AadIssuerVx properties

            // alternatively, we could build a valid issuer list and store that in a property
            // assuming the logic is
            // if ValidIssuers is set (excluding templated {tenantid} values from metadata), take those
            // if ValidIssuer is set, add to the Valid list (I believe this is what the aspnet OpenIdConnect internals do anyway)
            // if neither is set, use metadata discovery
            // then plow through the new valid issuer list

            SetIssuerPropertiesFromMetadata(securityToken);

            bool userDefinedExplicitIssuers = false;

            if (validationParameters.ValidIssuers != null)
            {
                var explicitIssuers = validationParameters.ValidIssuers.Where(x =>
                               !string.Equals(x, AadIssuerV1 ?? string.Empty, StringComparison.OrdinalIgnoreCase) &&
                               !string.Equals(x, AadIssuerV2 ?? string.Empty, StringComparison.OrdinalIgnoreCase));

                userDefinedExplicitIssuers = explicitIssuers != null && explicitIssuers.Any();

                var validIssuers = userDefinedExplicitIssuers ? explicitIssuers.ToList() : validationParameters.ValidIssuers;

                foreach (var validIssuerTemplate in validIssuers)
                {
                    if (IsValidIssuer(validIssuerTemplate, tenantId, actualIssuer))
                    {
                        return actualIssuer;
                    }
                }
            }

            if (validationParameters.ValidIssuer != null)
            {
                userDefinedExplicitIssuers = true;
                if (IsValidIssuer(validationParameters.ValidIssuer, tenantId, actualIssuer))
                {
                    return actualIssuer;
                }
            }

            try
            {
                if (!userDefinedExplicitIssuers)
                {
                    if (IsValidIssuer(AadIssuerV2, tenantId, actualIssuer))
                    {
                        return actualIssuer;
                    }

                    if (IsValidIssuer(AadIssuerV1, tenantId, actualIssuer))
                    {
                        return actualIssuer;
                    }
                }
            }
            catch
            {
            }

            // If a valid issuer is not found, throw
            throw new SecurityTokenInvalidIssuerException(
                string.Format(
                    CultureInfo.InvariantCulture,
                    IDWebErrorMessage.IssuerDoesNotMatchValidIssuers,
                    actualIssuer));
        }

        private string CreateV1Authority()
        {
            if (AadAuthority.Contains(Constants.Organizations, StringComparison.OrdinalIgnoreCase))
            {
                return AadAuthority.Replace($"{Constants.Organizations}/v2.0", Constants.Common, StringComparison.OrdinalIgnoreCase);
            }

            return AadAuthority.Replace("/v2.0", string.Empty, StringComparison.OrdinalIgnoreCase);
        }

        private ConfigurationManager<IssuerMetadata> CreateConfigManager(
            string aadAuthority)
        {
            if (AadIssuerValidatorOptions?.Value?.HttpClientName != null && HttpClientFactory != null)
            {
                return
                 new ConfigurationManager<IssuerMetadata>(
                     $"{aadAuthority}{Constants.OidcEndpoint}",
                     new IssuerConfigurationRetriever(),
                     HttpClientFactory.CreateClient(AadIssuerValidatorOptions.Value.HttpClientName));
            }
            else
            {
                return
                new ConfigurationManager<IssuerMetadata>(
                    $"{aadAuthority}{Constants.OidcEndpoint}",
                    new IssuerConfigurationRetriever());
            }
        }

        private bool IsValidIssuer(string validIssuerTemplate, string tenantId, string actualIssuer)
        {
            if (string.IsNullOrEmpty(validIssuerTemplate))
            {
                return false;
            }

            try
            {
                Uri issuerFromTemplateUri = new Uri(validIssuerTemplate.Replace("{tenantid}", tenantId, StringComparison.OrdinalIgnoreCase));
                Uri actualIssuerUri = new Uri(actualIssuer);

                return issuerFromTemplateUri.AbsoluteUri == actualIssuerUri.AbsoluteUri;
            }
            catch
            {
                // if something faults, ignore
            }

            return false;
        }

        /// <summary>Gets the tenant ID from a token.</summary>
        /// <param name="securityToken">A JWT token.</param>
        /// <returns>A string containing the tenant ID, if found or <see cref="string.Empty"/>.</returns>
        /// <remarks>Only <see cref="JwtSecurityToken"/> and <see cref="JsonWebToken"/> are acceptable types.</remarks>
        private static string GetTenantIdFromToken(SecurityToken securityToken)
        {
            if (securityToken is JwtSecurityToken jwtSecurityToken)
            {
                if (jwtSecurityToken.Payload.TryGetValue(ClaimConstants.Tid, out object? tid))
                {
                    return (string)tid;
                }

                jwtSecurityToken.Payload.TryGetValue(ClaimConstants.TenantId, out object? tenantId);
                if (tenantId != null)
                {
                    return (string)tenantId;
                }

                // Since B2C doesn't have "tid" as default, get it from issuer
                return GetTenantIdFromIss(jwtSecurityToken.Issuer);
            }

            if (securityToken is JsonWebToken jsonWebToken)
            {
                jsonWebToken.TryGetPayloadValue(ClaimConstants.Tid, out string? tid);
                if (tid != null)
                {
                    return tid;
                }

                jsonWebToken.TryGetPayloadValue(ClaimConstants.TenantId, out string? tenantId);
                if (tenantId != null)
                {
                    return tenantId;
                }

                // Since B2C doesn't have "tid" as default, get it from issuer
                return GetTenantIdFromIss(jsonWebToken.Issuer);
            }

            return string.Empty;
        }

        // The AAD "iss" claims contains the tenant ID in its value.
        // The URI can be
        // - {domain}/{tid}/v2.0
        // - {domain}/{tid}/v2.0/
        // - {domain}/{tfp}/{tid}/{userFlow}/v2.0/
        private static string GetTenantIdFromIss(string iss)
        {
            if (string.IsNullOrEmpty(iss))
            {
                return string.Empty;
            }

            var uri = new Uri(iss);

            if (uri.Segments.Length == 3)
            {
                return uri.Segments[1].TrimEnd('/');
            }

            if (uri.Segments.Length == 5 && uri.Segments[1].TrimEnd('/') == ClaimConstants.Tfp)
            {
                throw new SecurityTokenInvalidIssuerException(IDWebErrorMessage.B2CTfpIssuerNotSupported);
            }

            return string.Empty;
        }

        private void SetIssuerPropertiesFromMetadata(SecurityToken securityToken)
        {
            if (securityToken.Issuer.EndsWith("v2.0", StringComparison.OrdinalIgnoreCase))
            {
                if (AadIssuerV2 == null)
                {
                    IssuerMetadata issuerMetadata =
                        CreateConfigManager(AadAuthority).GetConfigurationAsync().ConfigureAwait(false).GetAwaiter().GetResult();
                    AadIssuerV2 = issuerMetadata.Issuer!;
                }
            }
            else
            {
                if (AadIssuerV1 == null)
                {
                    IssuerMetadata issuerMetadata =
                        CreateConfigManager(CreateV1Authority()).GetConfigurationAsync().ConfigureAwait(false).GetAwaiter().GetResult();
                    AadIssuerV1 = issuerMetadata.Issuer!;
                }
            }
        }
    }
}
