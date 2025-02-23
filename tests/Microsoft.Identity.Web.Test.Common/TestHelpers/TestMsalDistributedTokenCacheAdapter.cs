﻿// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web.TokenCacheProviders.Distributed;

namespace Microsoft.Identity.Web.Test.Common.TestHelpers
{
    public class TestMsalDistributedTokenCacheAdapter : MsalDistributedTokenCacheAdapter
    {
        /// <summary>
        /// This is standard text.
        /// </summary>
        /// <param name="distributedCache">l2.</param>
        /// <param name="distributedCacheOptions">l2 options.</param>
        /// <param name="logger">logger.</param>
        public TestMsalDistributedTokenCacheAdapter(
            IDistributedCache distributedCache,
            IOptions<MsalDistributedTokenCacheAdapterOptions> distributedCacheOptions,
            ILogger<MsalDistributedTokenCacheAdapter> logger,
            IServiceProvider serviceProvider = null)
            : base(distributedCache, distributedCacheOptions, logger, serviceProvider)
        {
        }

        public async Task TestRemoveKeyAsync(string cacheKey)
        {
            await RemoveKeyAsync(cacheKey).ConfigureAwait(false);
        }

        public async Task TestWriteCacheBytesAsync(string cacheKey, byte[] bytes)
        {
            await WriteCacheBytesAsync(cacheKey, bytes).ConfigureAwait(false);
        }

        public async Task<byte[]> TestReadCacheBytesAsync(string cacheKey)
        {
            return await ReadCacheBytesAsync(cacheKey).ConfigureAwait(false);
        }
    }
}
